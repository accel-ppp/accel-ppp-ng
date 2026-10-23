/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Per-interface counters of VPP-terminated sessions. They do not exist in
 * the kernel, so they are read from the VPP stats segment instead of netlink.
 *
 * A VPP sw_if_index is reused as soon as a session is deleted, so it is not
 * an identity. What identifies the counters of a session is
 *  - a baseline taken from a fresh read after its interface was created
 *  - the VPP instance generation the baseline was taken in
 *  - a final sample that is frozen before the interface is deleted
 */

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <linux/if_link.h>

#include <vppinfra/vec.h>
#include <vpp-api/client/stat_client.h>

#include "triton.h"
#include "ap_session.h"
#include "log.h"

#include "vpphooks.h"
#include "vppstats.h"

#define VPPSTATS_SOCKET "/run/vpp/stats.sock"
/* every session asks on the same timer tick, one dump serves all of them */
#define VPPSTATS_CACHE_SEC 1
/* epoch changes while dumping are transient, try again a few times */
#define VPPSTATS_RETRIES 3
#define VPPSTATS_RETRY_NSEC (2 * 1000 * 1000)
/* longest wait for VPP to finish updating the segment, the lock is held meanwhile */
#define VPPSTATS_TIMEOUT_NSEC (200ULL * 1000 * 1000)
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
#define VPPSTATS_STALL_SEC 60
#define VPPSTATS_UNREACH_SEC 60

struct vppstats_counter {
	uint64_t packets;
	uint64_t bytes;
};

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int connected;
/* bumped whenever the stats connection is dropped, sessions of an older one are lost */
static uint32_t inst_gen = 1;
static double last_hb;
static time_t last_hb_change;
static time_t unreach_since;
/* the stats socket the connection was made to, a different one is a new VPP */
static struct stat conn_sock;
static int conn_sock_valid;
static int snap_valid;
static time_t snap_ts;
static struct vppstats_counter *snap_rx, *snap_tx;
static uint32_t snap_len;

static time_t now_sec(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

static void snapshot_free(void)
{
	free(snap_rx);
	free(snap_tx);
	snap_rx = snap_tx = NULL;
	snap_len = 0;
	snap_valid = 0;
}

/* the connection is dropped, nothing read through it before can be trusted */
static void vppstats_instance_lost(void)
{
	if (connected) {
		stat_segment_disconnect();
		connected = 0;
	}
	snapshot_free();
	unreach_since = 0;
	inst_gen++;
	log_warn("vpp: stats segment lost, sessions of the previous VPP instance are no longer accounted\n");
}

static int vppstats_connect(void)
{
	if (stat_segment_connect(VPPSTATS_SOCKET))
		return -1;

	/* stat_segment_connect() clears the client state, so set this after it */
	stat_segment_set_timeout(VPPSTATS_TIMEOUT_NSEC);
	connected = 1;
	conn_sock_valid = !stat(VPPSTATS_SOCKET, &conn_sock);
	last_hb = 0;
	last_hb_change = now_sec();
	return 0;
}

/* the stats socket is not the one the connection was made to: VPP was restarted */
static int socket_replaced(void)
{
	struct stat st;

	if (!connected || !conn_sock_valid || stat(VPPSTATS_SOCKET, &st))
		return 0;
	return st.st_dev != conn_sock.st_dev || st.st_ino != conn_sock.st_ino ||
	       st.st_ctim.tv_sec != conn_sock.st_ctim.tv_sec ||
	       st.st_ctim.tv_nsec != conn_sock.st_ctim.tv_nsec;
}

/* sum the per-thread combined counters into snap[sw_if_index] */
static int snapshot_store(stat_segment_data_t *e, struct vppstats_counter **snap, uint32_t len)
{
	struct vppstats_counter *c;
	int t;

	if (e->type != STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED)
		return -1;

	c = calloc(len, sizeof(*c));
	if (!c)
		return -1;

	for (t = 0; t < vec_len(e->combined_counter_vec); t++) {
		uint32_t i;

		if (!e->combined_counter_vec[t])
			continue;
		for (i = 0; i < vec_len(e->combined_counter_vec[t]) && i < len; i++) {
			c[i].packets += e->combined_counter_vec[t][i].packets;
			c[i].bytes += e->combined_counter_vec[t][i].bytes;
		}
	}

	free(*snap);
	*snap = c;
	return 0;
}

/* one ls + dump, NULL if the directory epoch changed or VPP did not answer in time */
static stat_segment_data_t *vppstats_dump_counters(void)
{
	stat_segment_data_t *res = NULL;
	u8 **patterns = NULL;
	u32 *dir;
	int i;

	for (i = 0; i < VPPSTATS_RETRIES && !res; i++) {
		struct timespec ts = { 0, VPPSTATS_RETRY_NSEC };

		if (i)
			nanosleep(&ts, NULL);

		vec_add1(patterns, (u8 *)"/if/rx");
		vec_add1(patterns, (u8 *)"/if/tx");
		dir = stat_segment_ls(patterns);
		vec_free(patterns);
		if (!dir)
			continue;

		res = stat_segment_dump(dir);
		vec_free(dir);
	}

	return res;
}

static int vppstats_segment_unreachable(void)
{
	time_t now = now_sec();

	if (!unreach_since)
		unreach_since = now;
	if (now - unreach_since < VPPSTATS_UNREACH_SEC)
		return -EAGAIN;

	vppstats_instance_lost();
	return -ENODEV;
}

/*
 * Fill the snapshot from a fresh dump.
 * new_session: the caller starts a session, so it belongs to the VPP instance that is there now
 * 0 - OK, -EAGAIN - temporarily unavailable, -ENODEV - instance lost
 */
static int vppstats_refresh_snapshot(int new_session)
{
	stat_segment_data_t *res;
	uint32_t len = 0;
	double hb;
	int i, ret;
	int reconnected = 0;

again:
	/* a different stats socket is a restarted VPP, whatever its load */
	if (socket_replaced())
		vppstats_instance_lost();

	if (!connected && vppstats_connect())
		return vppstats_segment_unreachable();

	res = vppstats_dump_counters();
	if (!res)
		return vppstats_segment_unreachable();
	unreach_since = 0;

	/* after a successful ls, 0 means the epoch changed meanwhile, not a stall */
	hb = stat_segment_heartbeat();
	if (hb > 0) {
		if (hb != last_hb) {
			last_hb = hb;
			last_hb_change = now_sec();
		} else {
			if (now_sec() - last_hb_change >= VPPSTATS_STALL_SEC) {
				stat_segment_data_free(res);
				vppstats_instance_lost();
				/* a new session belongs to the new instance, so go on with it */
				if (new_session && !reconnected) {
					reconnected = 1;
					goto again;
				}
				return -ENODEV;
			}
		}
	}

	for (i = 0; i < vec_len(res); i++) {
		int t;

		if (res[i].type != STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED)
			continue;
		for (t = 0; t < vec_len(res[i].combined_counter_vec); t++)
			if (res[i].combined_counter_vec[t] && vec_len(res[i].combined_counter_vec[t]) > len)
				len = vec_len(res[i].combined_counter_vec[t]);
	}

	ret = 0;
	for (i = 0; i < vec_len(res); i++) {
		if (!strcmp(res[i].name, "/if/rx"))
			ret |= snapshot_store(&res[i], &snap_rx, len);
		else if (!strcmp(res[i].name, "/if/tx"))
			ret |= snapshot_store(&res[i], &snap_tx, len);
	}
	stat_segment_data_free(res);

	if (ret || !snap_rx || !snap_tx) {
		snapshot_free();
		return -EAGAIN;
	}

	snap_len = len;
	snap_ts = now_sec();
	snap_valid = 1;
	return 0;
}

static uint64_t sub_clamp(uint64_t a, uint64_t b)
{
	/* never wrap around, the counters of a reused index can be lower than the base */
	return a >= b ? a - b : 0;
}

static void counts_from_snapshot(struct vppstats_counts *c, uint32_t idx)
{
	c->rx_packets = snap_rx[idx].packets;
	c->rx_bytes = snap_rx[idx].bytes;
	c->tx_packets = snap_tx[idx].packets;
	c->tx_bytes = snap_tx[idx].bytes;
}

static void counts_to_stats(const struct vppstats_counts *c, struct rtnl_link_stats64 *stats)
{
	memset(stats, 0, sizeof(*stats));
	stats->rx_packets = c->rx_packets;
	stats->rx_bytes = c->rx_bytes;
	stats->tx_packets = c->tx_packets;
	stats->tx_bytes = c->tx_bytes;
}

/* fresh, uncached read of one session, 'new_session' also checks that the mapping is alive */
static int session_fresh_read(struct vpphook_private_data_t *pd, int new_session, struct vppstats_counts *raw)
{
	int ret = vppstats_refresh_snapshot(new_session);

	if (ret)
		return ret;
	if (pd->vpp_sw_if_index >= snap_len)
		return -EAGAIN;
	counts_from_snapshot(raw, pd->vpp_sw_if_index);
	return 0;
}

static void session_update_last(struct vppstats_session *s, const struct vppstats_counts *raw)
{
	s->last.rx_packets = sub_clamp(raw->rx_packets, s->base.rx_packets);
	s->last.rx_bytes = sub_clamp(raw->rx_bytes, s->base.rx_bytes);
	s->last.tx_packets = sub_clamp(raw->tx_packets, s->base.tx_packets);
	s->last.tx_bytes = sub_clamp(raw->tx_bytes, s->base.tx_bytes);
}

void vppstats_session_created(struct ap_session *ses)
{
	struct vpphook_private_data_t *pd = vpphook_get_pd(ses);

	if (!pd)
		return;

	pthread_mutex_lock(&lock);
	/* nothing cached before the interface existed may serve its index */
	snapshot_free();
	memset(&pd->stats, 0, sizeof(pd->stats));
	pthread_mutex_unlock(&lock);
}

int vppstats_read_stats(struct ap_session *ses, struct rtnl_link_stats64 *stats)
{
	struct vpphook_private_data_t *pd = vpphook_get_pd(ses);
	struct vppstats_session *s;
	struct vppstats_counts raw;
	int ret;

	/* sw_if_index 0 is local0, a session interface is never 0 */
	if (!pd || !pd->vpp_sw_if_index)
		return -1;
	s = &pd->stats;

	pthread_mutex_lock(&lock);

	if (s->frozen) {
		counts_to_stats(&s->last, stats);
		ret = 0;
		goto out;
	}

	if (s->base_valid && s->inst_gen != inst_gen) {
		ret = -ENODEV;
		goto out;
	}

	if (!s->base_valid) {
		/* first read of this session: baseline from a fresh read, never from the cache */
		ret = session_fresh_read(pd, 1, &raw);
		if (ret)
			goto out;
		s->base = raw;
		s->inst_gen = inst_gen;
		s->base_valid = 1;
	} else {
		/* a session created after the last snapshot is not in it, refresh then too */
		if (!snap_valid || pd->vpp_sw_if_index >= snap_len || now_sec() - snap_ts >= VPPSTATS_CACHE_SEC) {
			ret = session_fresh_read(pd, 0, &raw);
			if (ret)
				goto out;
		} else
			counts_from_snapshot(&raw, pd->vpp_sw_if_index);

		/* the refresh may have found a new VPP instance */
		if (s->inst_gen != inst_gen) {
			ret = -ENODEV;
			goto out;
		}
	}

	session_update_last(s, &raw);
	counts_to_stats(&s->last, stats);
	ret = 0;
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
	 * A fresh read, not the cache, so no traffic since the last refresh is
	 * missing. If it fails the last good value stays, which is also all
	 * there is when the instance is gone. From here on the VPP interface
	 * and its index must not be read for this session again.
	 */
	if (s->base_valid && s->inst_gen == inst_gen && pd->vpp_sw_if_index &&
	    !session_fresh_read(pd, 0, &raw) && s->inst_gen == inst_gen)
		session_update_last(s, &raw);

	s->frozen = 1;
out:
	pthread_mutex_unlock(&lock);
}

void vppstats_close(void)
{
	pthread_mutex_lock(&lock);
	snapshot_free();
	if (connected) {
		stat_segment_disconnect();
		connected = 0;
	}
	/* nothing read before can be matched with what a later connection shows */
	inst_gen++;
	pthread_mutex_unlock(&lock);
}
