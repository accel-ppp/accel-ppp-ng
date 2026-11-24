/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Per-interface counters of VPP-terminated sessions. They do not exist in
 * the kernel, so they are read from the VPP stats segment instead of netlink.
 *
 * A VPP sw_if_index is reused as soon as a session is deleted, so it is not
 * an identity. The identity of the counters is the ap_session: its
 * vpphook_private_data_t owns the VPP state of the session, that is the
 * sw_if_index and the struct vppstats_session with
 *  - the stats socket of the VPP instance the interface was created in, told by
 *    the socket file before and after the creation. The first read binds the
 *    session to a connection to that same socket, a different one means the
 *    index is not the interface of this session
 *  - the raw counters of the previous read and the total derived from them,
 *    which never goes down, also over a counter clear
 *  - a final sample that is frozen before the interface is deleted
 * VPP zeroes the counters of an interface when it creates it, also when it
 * reuses an index, so the counters of a session start from what VPP reports and no
 * baseline is needed. The counters of one interface are read in place from
 * the shared segment, the directory is not listed and the counters of the
 * other interfaces are not copied.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <linux/if_link.h>

#include <vppinfra/vec.h>
#include <vpp-api/client/stat_client.h>

#include "triton.h"
#include "ap_session.h"
#include "log.h"

#include "vpphooks.h"
#include "vppstats.h"

#ifndef VPPSTATS_SOCKET
#define VPPSTATS_SOCKET "/run/vpp/stats.sock"
#endif
/* VPP bumps the epoch whenever its directory changes, that is for every interface it creates:
 * a read that raced with it is repeated, a read takes microseconds */
#define VPPSTATS_READ_TRIES 10
/* the lookup of a directory entry is a listing, it fails while the directory changes */
#define VPPSTATS_RETRIES 3
#define VPPSTATS_RETRY_NSEC (2 * 1000 * 1000)
/* longest wait for VPP to finish updating the segment, the lock is held meanwhile */
#define VPPSTATS_TIMEOUT_NSEC (200ULL * 1000 * 1000)
/* all tries of one read together, the lock is held meanwhile */
#define VPPSTATS_READ_BUDGET_NSEC (300ULL * 1000 * 1000)
/* longest wait for the stats socket to hand out the segment descriptor */
#define VPPSTATS_PROBE_NSEC (100ULL * 1000 * 1000)
/* after a read or connect that failed, the next ones return -EAGAIN at once for this long */
#define VPPSTATS_BACKOFF_NSEC (1000ULL * 1000 * 1000)
/* during the backoff one final read may try, the next one only after this time */
#define VPPSTATS_FINAL_BYPASS_NSEC VPPSTATS_BACKOFF_NSEC
/*
 * A restart of VPP is told by its stats socket: a new instance creates a new
 * one, so the file differs from the one the connection was made to. A busy
 * VPP is not a restarted VPP: while many sessions come up, the directory
 * changes all the time, dumps fail for a while and the heartbeat is late, so
 * those only count after a long time and only as a fallback for a frozen
 * mapping.
 * - heartbeat stalled for VPPSTATS_STALL_SEC: reconnect, the instance is gone
 * - not reachable for VPPSTATS_UNREACH_SEC: the instance is gone
 * Shorter than that the stats are only temporarily unavailable.
 */
#ifndef VPPSTATS_STALL_SEC
#define VPPSTATS_STALL_SEC 60
#endif
#define VPPSTATS_UNREACH_SEC 60

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int connected;
/* bumped whenever the stats connection is dropped, sessions of an older one are lost */
static uint32_t inst_gen = 1;
static double last_hb;
static time_t last_hb_change;
static time_t unreach_since;
/* no attempt to read before this time (monotonic ns), set after a failed one */
static uint64_t backoff_until;
/* no further final read may bypass the backoff before this time (monotonic ns) */
static uint64_t final_bypass_until;
/* the stats socket the connection was made to, a different one is a new VPP */
static struct vppstats_sockid conn_sock;
/* the directory entries of /if/rx and /if/tx, looked up by name once per connection */
static int dir_valid;
static uint32_t dir_rx, dir_tx;

static uint64_t vppstats_now_nsec(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static time_t vppstats_now_sec(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

/* the connection is dropped, nothing read through it before can be trusted */
static void vppstats_instance_lost(void)
{
	if (connected) {
		stat_segment_disconnect();
		connected = 0;
	}
	dir_valid = 0;
	unreach_since = 0;
	backoff_until = 0;
	final_bypass_until = 0;
	inst_gen++;
	log_warn("vpp: stats segment lost, sessions of the previous VPP instance are no longer accounted\n");
}

static int vppstats_get_sockid(struct vppstats_sockid *id)
{
	struct stat st;

	if (stat(VPPSTATS_SOCKET, &st))
		return -1;
	id->dev = st.st_dev;
	id->ino = st.st_ino;
	id->mtim = st.st_mtim;
	return 0;
}

static int vppstats_sockid_equal(const struct vppstats_sockid *a, const struct vppstats_sockid *b)
{
	return a->dev == b->dev && a->ino == b->ino && a->mtim.tv_sec == b->mtim.tv_sec &&
	       a->mtim.tv_nsec == b->mtim.tv_nsec;
}

/*
 * stat_segment_connect() waits for the segment descriptor without a limit,
 * and the lock is held meanwhile. A VPP that accepts the connection but is
 * stuck never sends it. So the socket is asked once on our own, with a time
 * limit, before the library is used: a VPP that does not answer in time is
 * not connected to. The descriptor of the probe is not needed.
 * 0 - the socket answered, -1 - it did not
 */
int vppstats_probe(const char *path)
{
	struct sockaddr_un un = { .sun_family = AF_UNIX };
	char byte, ctl[CMSG_SPACE(sizeof(int))];
	struct iovec io = { .iov_base = &byte, .iov_len = sizeof(byte) };
	struct msghdr msg = { .msg_iov = &io, .msg_iovlen = 1, .msg_control = ctl, .msg_controllen = sizeof(ctl) };
	struct cmsghdr *cmsg;
	struct pollfd pfd;
	int fd, ret = -1;

	if (strlen(path) >= sizeof(un.sun_path))
		return -1;
	strcpy(un.sun_path, path);

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	if (connect(fd, (struct sockaddr *)&un, sizeof(un)))
		goto out;

	pfd.fd = fd;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, VPPSTATS_PROBE_NSEC / 1000000) != 1)
		goto out;
	if (recvmsg(fd, &msg, MSG_DONTWAIT | MSG_CMSG_CLOEXEC) < 0)
		goto out;

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
			int sent;

			memcpy(&sent, CMSG_DATA(cmsg), sizeof(sent));
			close(sent);
			ret = 0;
		}
out:
	close(fd);
	return ret;
}

static int vppstats_connect(void)
{
	struct vppstats_sockid before, after;

	/*
	 * The socket the connection goes to is the one that is there before and
	 * after connecting. If VPP was restarted meanwhile, the connection may
	 * be to the old instance while the file is the new one.
	 */
	if (vppstats_get_sockid(&before) || vppstats_probe(VPPSTATS_SOCKET) || stat_segment_connect(VPPSTATS_SOCKET))
		return -1;

	if (vppstats_get_sockid(&after) || !vppstats_sockid_equal(&before, &after)) {
		stat_segment_disconnect();
		return -1;
	}

	/* stat_segment_connect() clears the client state, so set this after it */
	stat_segment_set_timeout(VPPSTATS_TIMEOUT_NSEC);
	connected = 1;
	dir_valid = 0;
	conn_sock = after;
	last_hb = 0;
	last_hb_change = vppstats_now_sec();
	return 0;
}

/*
 * The stats socket is not the one the connection was made to: VPP was restarted.
 * The modification time is set when the socket is bound, unlike the change
 * time it does not move with a chmod or chown of the file.
 */
static int vppstats_socket_replaced(void)
{
	struct vppstats_sockid id;

	if (!connected || vppstats_get_sockid(&id))
		return 0;
	return !vppstats_sockid_equal(&id, &conn_sock);
}

/*
 * Every wait for the segment of one read, lookups and heartbeat included, comes
 * out of one budget. 0 - the wait of the next step is set, -1 - nothing is left.
 */
static int vppstats_arm_timeout(uint64_t deadline)
{
	uint64_t now = vppstats_now_nsec();

	if (now >= deadline)
		return -1;
	stat_client_main.timeout = deadline - now < VPPSTATS_TIMEOUT_NSEC ? deadline - now : VPPSTATS_TIMEOUT_NSEC;
	return 0;
}

/* directory index of the one entry that matches the pattern, -1 if it is not there or the listing failed */
static int vppstats_lookup_entry(const char *pattern, uint32_t *index, uint64_t deadline)
{
	u8 **patterns = NULL;
	u32 *dir = NULL;
	int i, ret = -1;

	for (i = 0; i < VPPSTATS_RETRIES && !dir; i++) {
		struct timespec ts = { 0, VPPSTATS_RETRY_NSEC };

		if (i)
			nanosleep(&ts, NULL);
		if (vppstats_arm_timeout(deadline))
			break;

		vec_add1(patterns, (u8 *)pattern);
		dir = stat_segment_ls(patterns);
		vec_free(patterns);
	}

	if (dir && vec_len(dir) == 1) {
		*index = dir[0];
		ret = 0;
	}
	vec_free(dir);
	return ret;
}

static int vppstats_lookup_entries(uint64_t deadline)
{
	if (vppstats_lookup_entry("^/if/rx$", &dir_rx, deadline) || vppstats_lookup_entry("^/if/tx$", &dir_tx, deadline))
		return -1;
	dir_valid = 1;
	return 0;
}

/*
 * Add the counters of one interface of a combined counter entry, over all
 * threads. 0 - OK, -EAGAIN - the index is in none of the vectors yet,
 * -ENOENT - the entry is not the one that was looked up
 */
static int vppstats_sum_entry(stat_client_main_t *sm, vlib_stats_entry_t *e, const char *name, uint32_t idx,
			      uint64_t *packets, uint64_t *bytes)
{
	vlib_counter_t **threads, *c;
	int t, seen = 0;

	if (strcmp(e->name, name) || e->type != STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED)
		return -ENOENT;

	threads = stat_segment_adjust(sm, e->data);
	if (!threads)
		return -ENOENT;

	*packets = *bytes = 0;
	for (t = 0; t < stat_segment_vec_len(threads); t++) {
		c = stat_segment_adjust(sm, threads[t]);
		if (!c || idx >= (uint32_t)stat_segment_vec_len(c))
			continue;
		*packets += c[idx].packets;
		*bytes += c[idx].bytes;
		seen = 1;
	}

	return seen ? 0 : -EAGAIN;
}

/*
 * One read of rx and tx of an interface, valid only if the directory did not
 * change meanwhile (a changed epoch repeats the read).
 * 0 - OK, -EAGAIN - the interface is not in the counters yet, -ENOENT - the
 * entries are not where they were looked up, -EIO - no consistent read
 */
static int vppstats_read_once(uint32_t idx, struct vppstats_counts *raw, uint64_t deadline)
{
	stat_client_main_t *sm = &stat_client_main;
	int i;

	for (i = 0; i < VPPSTATS_READ_TRIES; i++) {
		stat_segment_access_t sa;
		struct vppstats_counts c = { 0 };
		int ret = -ENOENT;

		if (vppstats_arm_timeout(deadline))
			break;

		if (stat_segment_access_start(&sa, sm))
			continue;

		if (sm->directory_vector && dir_rx < (uint32_t)stat_segment_vec_len(sm->directory_vector) &&
		    dir_tx < (uint32_t)stat_segment_vec_len(sm->directory_vector)) {
			ret = vppstats_sum_entry(sm, &sm->directory_vector[dir_rx], "/if/rx", idx, &c.rx_packets, &c.rx_bytes);
			if (!ret)
				ret = vppstats_sum_entry(sm, &sm->directory_vector[dir_tx], "/if/tx", idx, &c.tx_packets,
							 &c.tx_bytes);
		}

		if (!stat_segment_access_end(&sa, sm))
			continue;

		if (!ret) {
			*raw = c;
			/*
			 * The entries are the ones looked up and the read was consistent,
			 * so this is the directory as the client knows it. The library
			 * compares the epoch with this one and gives no heartbeat (0) if it
			 * differs, and only a listing sets it. VPP changes the epoch for
			 * every interface it creates, without this the stall check below
			 * would hardly ever run.
			 */
			sm->current_epoch = sa.epoch;
		}
		return ret;
	}

	return -EIO;
}

static int vppstats_segment_unreachable(void)
{
	time_t now = vppstats_now_sec();

	backoff_until = vppstats_now_nsec() + VPPSTATS_BACKOFF_NSEC;
	if (!unreach_since)
		unreach_since = now;
	if (now - unreach_since < VPPSTATS_UNREACH_SEC)
		return -EAGAIN;

	vppstats_instance_lost();
	return -ENODEV;
}

/*
 * Read the raw counters of one interface of the session s.
 * 0 - OK, -EAGAIN - temporarily unavailable, -ENODEV - instance lost
 * A final read may try during the backoff: it is the last one and the traffic
 * since the previous read would be lost. Only one may do that per
 * VPPSTATS_FINAL_BYPASS_NSEC, so a burst of terminating sessions on a stalled
 * segment does not hold the lock one budget after the other. The others get
 * -EAGAIN and keep the total they have.
 */
static int vppstats_read_counters_locked(struct vppstats_session *s, uint32_t idx, struct vppstats_counts *raw, int final,
					 uint64_t deadline)
{
	double hb;
	int ret;
	int relooked = 0;

	/* the last attempt failed a moment ago, do not hold the lock for another one */
	if (backoff_until && vppstats_now_nsec() < backoff_until) {
		if (!final || vppstats_now_nsec() < final_bypass_until)
			return -EAGAIN;
		final_bypass_until = vppstats_now_nsec() + VPPSTATS_FINAL_BYPASS_NSEC;
	}

again:
	/* a different stats socket is a restarted VPP, whatever its load */
	if (vppstats_socket_replaced())
		vppstats_instance_lost();

	if (!connected && vppstats_connect())
		return vppstats_segment_unreachable();

	/*
	 * The first read binds the session to the connection: it must be the
	 * instance the interface was created in, otherwise the index is not
	 * the interface of this session.
	 */
	if (s->pending) {
		if (!vppstats_sockid_equal(&conn_sock, &s->sock)) {
			s->valid = 0;
			s->pending = 0;
			return -ENODEV;
		}
		s->inst_gen = inst_gen;
		s->pending = 0;
	}

	if (!dir_valid && vppstats_lookup_entries(deadline))
		return vppstats_segment_unreachable();

	ret = vppstats_read_once(idx, raw, deadline);
	if (ret == -ENOENT && !relooked) {
		/* the directory was rebuilt, find the entries again */
		relooked = 1;
		dir_valid = 0;
		goto again;
	}
	if (ret == -ENOENT || ret == -EIO)
		return vppstats_segment_unreachable();
	unreach_since = 0;
	backoff_until = 0;
	final_bypass_until = 0;

	/* 0 means the epoch changed after the read, not a stall */
	hb = vppstats_arm_timeout(deadline) ? 0 : stat_segment_heartbeat();
	if (hb > 0) {
		if (hb != last_hb) {
			last_hb = hb;
			last_hb_change = vppstats_now_sec();
		} else if (vppstats_now_sec() - last_hb_change >= VPPSTATS_STALL_SEC) {
			vppstats_instance_lost();
			return -ENODEV;
		}
	}

	return ret;
}

static int vppstats_read_counters(struct vppstats_session *s, uint32_t idx, struct vppstats_counts *raw, int final)
{
	int ret;

	ret = vppstats_read_counters_locked(s, idx, raw, final, vppstats_now_nsec() + VPPSTATS_READ_BUDGET_NSEC);
	stat_client_main.timeout = VPPSTATS_TIMEOUT_NSEC;
	return ret;
}

static void vppstats_counts_to_stats(const struct vppstats_counts *c, struct rtnl_link_stats64 *stats)
{
	memset(stats, 0, sizeof(*stats));
	stats->rx_packets = c->rx_packets;
	stats->rx_bytes = c->rx_bytes;
	stats->tx_packets = c->tx_packets;
	stats->tx_bytes = c->tx_bytes;
}

/* read of the counters of one session */
static int vppstats_session_counters(struct vpphook_private_data_t *pd, struct vppstats_counts *raw, int final)
{
	return vppstats_read_counters(&pd->stats, pd->vpp_sw_if_index, raw, final);
}

/* the session can be read: it has an interface in the instance it is bound to, or is not bound yet */
static int vppstats_session_readable(const struct vpphook_private_data_t *pd)
{
	const struct vppstats_session *s = &pd->stats;

	return pd->vpp_sw_if_index && s->valid && (s->pending || s->inst_gen == inst_gen);
}

/*
 * A VPP counter clear resets the raw values to zero. The total of the session
 * must not go down, so the part since the previous read is added and a raw
 * value below the previous one is taken as a clear: what it counts is what came
 * after the reset. A clear is only seen if the raw value is below the previous
 * one at the next read. Traffic between the last read and the clear is not
 * counted, and if the new value has already passed the old one, the total is
 * short by up to the old raw value as well.
 */
static void vppstats_session_update(struct vppstats_session *s, const struct vppstats_counts *raw)
{
#define VPPSTATS_ADD(field) \
	s->total.field += raw->field >= s->raw_last.field ? raw->field - s->raw_last.field : raw->field

	VPPSTATS_ADD(rx_packets);
	VPPSTATS_ADD(rx_bytes);
	VPPSTATS_ADD(tx_packets);
	VPPSTATS_ADD(tx_bytes);
#undef VPPSTATS_ADD

	s->raw_last = *raw;
}

void vppstats_session_prepare(struct ap_session *ses)
{
	struct vpphook_private_data_t *pd = vpphook_get_pd(ses);

	if (!pd)
		return;

	pthread_mutex_lock(&lock);
	/* a new session starts from zero, whatever the index had before */
	memset(&pd->stats, 0, sizeof(pd->stats));
	/*
	 * The instance is told by its socket, read from the file and not from
	 * a connection: a connection may not be there, or still be one to the
	 * instance before a restart.
	 */
	if (!vppstats_get_sockid(&pd->stats.sock))
		pd->stats.pending = 1;
	pthread_mutex_unlock(&lock);
}

void vppstats_session_created(struct ap_session *ses)
{
	struct vpphook_private_data_t *pd = vpphook_get_pd(ses);
	struct vppstats_sockid id;

	if (!pd)
		return;

	pthread_mutex_lock(&lock);
	/*
	 * The socket is the same as before the interface was created, so the interface is in
	 * that instance. If VPP was restarted meanwhile, the interface is in the old one or
	 * in none, and the session has no counters.
	 */
	if (pd->stats.pending && !vppstats_get_sockid(&id) && vppstats_sockid_equal(&id, &pd->stats.sock))
		pd->stats.valid = 1;
	else {
		pd->stats.pending = 0;
		log_warn("vpp: the VPP instance of session %s is not known, its counters are not read\n", ses->sessionid);
	}
	pthread_mutex_unlock(&lock);
}

int vppstats_read_stats(struct ap_session *ses, struct rtnl_link_stats64 *stats)
{
	struct vpphook_private_data_t *pd = vpphook_get_pd(ses);
	struct vppstats_session *s;
	struct vppstats_counts raw;
	int ret;

	if (!pd)
		return -1;
	s = &pd->stats;

	pthread_mutex_lock(&lock);

	/* the final sample stays after the interface is gone */
	if (s->frozen) {
		vppstats_counts_to_stats(&s->total, stats);
		ret = 0;
		goto out;
	}

	/*
	 * sw_if_index 0 is local0, a session interface is never 0. Besides, the session
	 * was not created by the hook, or its VPP instance or counters are gone.
	 */
	if (!vppstats_session_readable(pd)) {
		ret = -ENODEV;
		goto out;
	}

	ret = vppstats_session_counters(pd, &raw, 0);
	if (ret)
		goto out;

	/* the read may have found a new VPP instance */
	if (!s->valid || s->pending || s->inst_gen != inst_gen) {
		ret = -ENODEV;
		goto out;
	}

	vppstats_session_update(s, &raw);
	vppstats_counts_to_stats(&s->total, stats);
out:
	pthread_mutex_unlock(&lock);
	return ret;
}

void vppstats_session_freeze(struct ap_session *ses)
{
	struct vpphook_private_data_t *pd = vpphook_get_pd(ses);
	struct vppstats_session *s;
	struct vppstats_counts raw;

	if (!pd)
		return;
	s = &pd->stats;

	pthread_mutex_lock(&lock);

	if (s->frozen)
		goto out;

	/*
	 * A read now, so no traffic since the last one is missing. If it fails
	 * the last good value stays, which is also all there is when the
	 * instance is gone. From here on the VPP interface and its index must
	 * not be read for this session again.
	 */
	if (vppstats_session_readable(pd) && !vppstats_session_counters(pd, &raw, 1) && s->valid && !s->pending &&
	    s->inst_gen == inst_gen)
		vppstats_session_update(s, &raw);

	s->frozen = 1;
out:
	pthread_mutex_unlock(&lock);
}

void vppstats_close(void)
{
	pthread_mutex_lock(&lock);
	dir_valid = 0;
	unreach_since = 0;
	backoff_until = 0;
	final_bypass_until = 0;
	if (connected) {
		stat_segment_disconnect();
		connected = 0;
	}
	/* nothing read before can be matched with what a later connection shows */
	inst_gen++;
	pthread_mutex_unlock(&lock);
}
