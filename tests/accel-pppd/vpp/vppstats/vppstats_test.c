/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
/*
 * Tests of the session counters of the VPP plugin (vppstats.c) without VPP.
 * vppstats.c is built as it is, against a fake of the VPP stats client
 * (fake_stat_client.c) whose segment the test fills. The stats socket of the
 * VPP instance is a file in a temporary directory, VPPSTATS_SOCKET.
 *
 * ./vppstats_test --list   the names of the tests
 * ./vppstats_test NAME     run one test, exit status 0 if it passed
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "ap_session.h"
#include "vpphooks.h"
#include "vppstats.h"
#include "fake_stat.h"

#define BACKOFF_WAIT_US 1100000
#define MAX_SESSIONS 8

static int failed;
static int warnings;

#define CHECK(cond)                                                                                                    \
	do {                                                                                                           \
		if (!(cond)) {                                                                                         \
			printf("  %s:%d: check failed: %s\n", __FILE__, __LINE__, #cond);                               \
			failed = 1;                                                                                    \
		}                                                                                                      \
	} while (0)

/* what the plugin needs from the rest of accel-pppd */
void log_warn(const char *fmt, ...)
{
	(void)fmt;
	warnings++;
}

static struct {
	struct ap_session ses;
	struct vpphook_private_data_t pd;
} sessions[MAX_SESSIONS];
static int nsessions;

struct vpphook_private_data_t *vpphook_get_pd(struct ap_session *ses)
{
	int i;

	for (i = 0; i < nsessions; i++)
		if (&sessions[i].ses == ses)
			return &sessions[i].pd;
	return NULL;
}

/*
 * The stats socket of a VPP instance: a new instance has a new socket file.
 * It is a real listening socket, a thread hands the segment descriptor (here
 * the descriptor of /dev/null) to everyone who connects, like VPP does. A stuck
 * VPP accepts nothing: connecting works through the backlog, nothing is sent.
 */
static pthread_mutex_t srv_lock = PTHREAD_MUTEX_INITIALIZER;
static int srv_fd = -1;
static int srv_hang;
static pthread_t srv_thread;
static int srv_started;

static void srv_send_fd(int conn)
{
	char byte = 0, ctl[CMSG_SPACE(sizeof(int))] = { 0 };
	struct iovec io = { .iov_base = &byte, .iov_len = 1 };
	struct msghdr msg = { .msg_iov = &io, .msg_iovlen = 1, .msg_control = ctl, .msg_controllen = sizeof(ctl) };
	struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
	int nul = open("/dev/null", O_RDONLY);

	c->cmsg_level = SOL_SOCKET;
	c->cmsg_type = SCM_RIGHTS;
	c->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(c), &nul, sizeof(int));
	sendmsg(conn, &msg, MSG_NOSIGNAL);
	close(nul);
}

static void *srv_main(void *arg)
{
	(void)arg;
	for (;;) {
		pthread_mutex_lock(&srv_lock);
		if (srv_fd >= 0 && !srv_hang) {
			int conn = accept4(srv_fd, NULL, NULL, SOCK_CLOEXEC);

			if (conn >= 0) {
				srv_send_fd(conn);
				close(conn);
			}
		}
		pthread_mutex_unlock(&srv_lock);
		usleep(2000);
	}
	return NULL;
}

static void sock_new(void)
{
	static long seq;
	struct timespec times[2] = { { 1000000 + ++seq, 0 }, { 1000000 + seq, 0 } };
	struct sockaddr_un un = { .sun_family = AF_UNIX };

	pthread_mutex_lock(&srv_lock);
	if (srv_fd >= 0)
		close(srv_fd);
	unlink(VPPSTATS_SOCKET);
	strcpy(un.sun_path, VPPSTATS_SOCKET);
	srv_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (srv_fd >= 0 && (bind(srv_fd, (struct sockaddr *)&un, sizeof(un)) || listen(srv_fd, 8))) {
		close(srv_fd);
		srv_fd = -1;
	}
	utimensat(AT_FDCWD, VPPSTATS_SOCKET, times, 0);
	if (!srv_started) {
		srv_started = 1;
		pthread_create(&srv_thread, NULL, srv_main, NULL);
	}
	pthread_mutex_unlock(&srv_lock);
}

/* the socket is gone: VPP is not running */
static void sock_remove(void)
{
	pthread_mutex_lock(&srv_lock);
	if (srv_fd >= 0)
		close(srv_fd);
	srv_fd = -1;
	unlink(VPPSTATS_SOCKET);
	pthread_mutex_unlock(&srv_lock);
}

static void reset(void)
{
	srv_hang = 0;
	vppstats_close();
	fake_reset();
	sock_new();
	warnings = 0;
	nsessions = 0;
}

/* a session as the hook creates it: instance noted, interface made, index known */
static struct ap_session *new_session(uint32_t idx)
{
	struct ap_session *ses = &sessions[nsessions].ses;
	struct vpphook_private_data_t *pd = &sessions[nsessions].pd;

	nsessions++;
	memset(ses, 0, sizeof(*ses));
	memset(pd, 0, sizeof(*pd));
	vppstats_session_prepare(ses);
	pd->vpp_sw_if_index = idx;
	vppstats_session_created(ses);
	return ses;
}

static int rd(struct ap_session *ses, uint64_t *rx_packets, uint64_t *tx_bytes)
{
	struct rtnl_link_stats64 st = { 0 };
	int ret = vppstats_read_stats(ses, &st);

	if (rx_packets)
		*rx_packets = st.rx_packets;
	if (tx_bytes)
		*tx_bytes = st.tx_bytes;
	return ret;
}

static long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* the counters are only added up, over the threads, and a session counts what VPP counts from zero */
static void t_delta_accumulation(void)
{
	struct ap_session *ses;
	uint64_t rx, tx;

	reset();
	fake_set_counters(5, 11, 1100, 7, 700);
	ses = new_session(5);
	CHECK(rd(ses, &rx, &tx) == 0 && rx == 11 && tx == 700);
	fake_set_counters(5, 25, 2500, 9, 900);
	CHECK(rd(ses, &rx, &tx) == 0 && rx == 25 && tx == 900);
	/* no new traffic: nothing is added twice */
	CHECK(rd(ses, &rx, &tx) == 0 && rx == 25 && tx == 900);
}

/* creating a session does not connect, the first read does and binds the session */
static void t_bind_at_first_read(void)
{
	struct ap_session *ses;

	reset();
	ses = new_session(3);
	CHECK(fake.connect_calls == 0);
	CHECK(rd(ses, NULL, NULL) == 0);
	CHECK(fake.connect_calls == 1);
	CHECK(rd(ses, NULL, NULL) == 0);
	CHECK(fake.connect_calls == 1);
}

/* a raw value below the previous one is a clear: the session stays up, its total never goes down */
static void t_counter_clear(void)
{
	struct ap_session *ses;
	uint64_t rx, tx;

	reset();
	ses = new_session(4);
	fake_set_counters(4, 100, 10000, 100, 10000);
	CHECK(rd(ses, &rx, &tx) == 0 && rx == 100 && tx == 10000);
	fake_set_counters(4, 5, 500, 5, 500);
	CHECK(rd(ses, &rx, &tx) == 0 && rx == 105 && tx == 10500);
	fake_set_counters(4, 8, 800, 8, 800);
	CHECK(rd(ses, &rx, &tx) == 0 && rx == 108 && tx == 10800);
}

/* a read that raced with a change of the directory is repeated */
static void t_epoch_race_retry(void)
{
	struct ap_session *ses;
	uint64_t rx;

	reset();
	fake_set_counters(6, 40, 4000, 40, 4000);
	ses = new_session(6);
	fake.epoch_fail = 3;
	CHECK(rd(ses, &rx, NULL) == 0 && rx == 40);
}

/* an index that is in no counter vector yet is only temporarily unavailable */
static void t_unknown_index_eagain(void)
{
	struct ap_session *ses;

	reset();
	ses = new_session(FAKE_IFACES + 6);
	CHECK(rd(ses, NULL, NULL) == -EAGAIN);
	CHECK(warnings == 0);
}

/* a segment that is being updated: all waits of a read together stay within the budget */
static void t_stall_budget(void)
{
	struct ap_session *ses;
	long t;

	reset();
	ses = new_session(5);
	CHECK(rd(ses, NULL, NULL) == 0);
	fake.stall = 1;
	t = now_ms();
	CHECK(rd(ses, NULL, NULL) == -EAGAIN);
	t = now_ms() - t;
	printf("  read took %ld ms\n", t);
	CHECK(t >= 250 && t < 400);
}

/* the same for the first read of a session, which also looks up the directory */
static void t_lookup_budget(void)
{
	struct ap_session *ses;
	long t;

	reset();
	ses = new_session(5);
	fake.stall = 1;
	t = now_ms();
	CHECK(rd(ses, NULL, NULL) == -EAGAIN);
	t = now_ms() - t;
	printf("  read took %ld ms\n", t);
	CHECK(t >= 250 && t < 400);
}

/* after a failed read the next ones return at once and do not touch the segment */
static void t_stall_backoff(void)
{
	struct ap_session *ses;
	uint64_t rx;
	int calls;
	long t;

	reset();
	fake_set_counters(5, 10, 100, 10, 100);
	ses = new_session(5);
	CHECK(rd(ses, &rx, NULL) == 0 && rx == 10);
	fake.stall = 1;
	CHECK(rd(ses, NULL, NULL) == -EAGAIN);
	calls = fake.access_calls;
	t = now_ms();
	CHECK(rd(ses, NULL, NULL) == -EAGAIN);
	CHECK(now_ms() - t < 50);
	CHECK(fake.access_calls == calls);

	/* the backoff ends, the session was not lost */
	fake.stall = 0;
	fake_set_counters(5, 30, 300, 30, 300);
	usleep(BACKOFF_WAIT_US);
	CHECK(rd(ses, &rx, NULL) == 0 && rx == 30);
	CHECK(warnings == 0);
}

/* the final sample is taken even during the backoff, nothing since the last read is lost */
static void t_final_read_ignores_backoff(void)
{
	struct ap_session *ses;
	uint64_t rx;

	reset();
	fake_set_counters(5, 10, 100, 10, 100);
	ses = new_session(5);
	CHECK(rd(ses, &rx, NULL) == 0 && rx == 10);
	fake.stall = 1;
	CHECK(rd(ses, NULL, NULL) == -EAGAIN);
	fake.stall = 0;
	fake_set_counters(5, 70, 700, 70, 700);
	CHECK(rd(ses, NULL, NULL) == -EAGAIN);
	vppstats_session_freeze(ses);
	CHECK(rd(ses, &rx, NULL) == 0 && rx == 70);
}

/* a burst of final reads on a stalled segment: one tries, the others do not hold the lock */
static void t_final_reads_share_backoff(void)
{
	struct ap_session *ses[5];
	int calls, i;
	long t;

	reset();
	for (i = 0; i < 5; i++) {
		fake_set_counters(5 + i, 10, 100, 10, 100);
		ses[i] = new_session(5 + i);
		CHECK(rd(ses[i], NULL, NULL) == 0);
	}
	fake.stall = 1;
	CHECK(rd(ses[0], NULL, NULL) == -EAGAIN);

	/* the first final read tries during the backoff and runs into the budget */
	t = now_ms();
	vppstats_session_freeze(ses[0]);
	t = now_ms() - t;
	printf("  first final read took %ld ms\n", t);
	CHECK(t >= 250 && t < 400);

	/* the next ones return at once and do not touch the segment */
	calls = fake.access_calls;
	t = now_ms();
	for (i = 1; i < 4; i++)
		vppstats_session_freeze(ses[i]);
	t = now_ms() - t;
	printf("  three more final reads took %ld ms\n", t);
	CHECK(t < 50);
	CHECK(fake.access_calls == calls);

	/* after the time one final read tries again */
	usleep(BACKOFF_WAIT_US);
	t = now_ms();
	vppstats_session_freeze(ses[4]);
	t = now_ms() - t;
	CHECK(t >= 250 && t < 400);
}

/* the final sample stays, the segment and the index are not read for the session any more */
static void t_frozen_total(void)
{
	struct ap_session *ses;
	struct vpphook_private_data_t *pd;
	uint64_t rx;
	int calls;

	reset();
	fake_set_counters(5, 10, 100, 10, 100);
	ses = new_session(5);
	CHECK(rd(ses, NULL, NULL) == 0);
	fake_set_counters(5, 50, 500, 50, 500);
	vppstats_session_freeze(ses);
	calls = fake.access_calls;

	/* the index is reused by another interface and VPP counts there */
	pd = vpphook_get_pd(ses);
	pd->vpp_sw_if_index = 0;
	fake_set_counters(5, 9999, 9999, 9999, 9999);
	CHECK(rd(ses, &rx, NULL) == 0 && rx == 50);
	vppstats_session_freeze(ses);
	CHECK(rd(ses, &rx, NULL) == 0 && rx == 50);
	CHECK(fake.access_calls == calls);
}

/* a bound session of a VPP that was restarted: no counters of the new instance, not even for a reused index */
static void t_instance_replaced_bound(void)
{
	struct ap_session *old, *young;
	uint64_t rx;

	reset();
	fake_set_counters(5, 10, 100, 10, 100);
	old = new_session(5);
	CHECK(rd(old, NULL, NULL) == 0);

	sock_new();
	fake_set_counters(5, 3, 30, 3, 30);
	CHECK(rd(old, NULL, NULL) == -ENODEV);
	CHECK(warnings >= 1);

	/* a session of the new instance reads from it, the old one never does */
	young = new_session(5);
	CHECK(rd(young, &rx, NULL) == 0 && rx == 3);
	CHECK(rd(old, NULL, NULL) == -ENODEV);
}

/* not bound yet when VPP is restarted: the connection is to the new instance, the session is not read from it */
static void t_instance_replaced_pending(void)
{
	struct ap_session *ses;
	int calls;

	reset();
	ses = new_session(5);
	sock_new();
	calls = fake.access_calls;
	CHECK(rd(ses, NULL, NULL) == -ENODEV);
	CHECK(fake.access_calls == calls);
	CHECK(rd(ses, NULL, NULL) == -ENODEV);
}

/* VPP is restarted while the interface is created: the interface is in the old instance or in none */
static void t_instance_replaced_during_creation(void)
{
	struct ap_session *ses = &sessions[0].ses;
	struct vpphook_private_data_t *pd = &sessions[0].pd;

	reset();
	nsessions = 1;
	memset(ses, 0, sizeof(*ses));
	memset(pd, 0, sizeof(*pd));
	vppstats_session_prepare(ses);
	pd->vpp_sw_if_index = 5;
	sock_new();
	vppstats_session_created(ses);
	CHECK(warnings >= 1);
	CHECK(rd(ses, NULL, NULL) == -ENODEV);
	CHECK(fake.access_calls == 0 && fake.connect_calls == 0);
}

/* no stats socket when the interface is created: the instance is not known, the session is never read */
static void t_no_socket_at_creation(void)
{
	struct ap_session *ses;

	reset();
	unlink(VPPSTATS_SOCKET);
	ses = new_session(5);
	CHECK(warnings >= 1);
	sock_new();
	CHECK(rd(ses, NULL, NULL) == -ENODEV);
	CHECK(fake.access_calls == 0 && fake.connect_calls == 0);
}

/* no connection to the segment yet: temporarily unavailable, the session binds once it is there */
static void t_connect_failure_pending(void)
{
	struct ap_session *ses;
	uint64_t rx;

	reset();
	fake_set_counters(5, 12, 120, 12, 120);
	ses = new_session(5);
	fake.connect_ok = 0;
	CHECK(rd(ses, NULL, NULL) == -EAGAIN);
	CHECK(rd(ses, NULL, NULL) == -EAGAIN);
	CHECK(fake.connect_calls == 1);

	fake.connect_ok = 1;
	usleep(BACKOFF_WAIT_US);
	CHECK(rd(ses, &rx, NULL) == 0 && rx == 12);
	CHECK(warnings == 0);
}

static void replace_socket(void)
{
	sock_new();
}

/* VPP is restarted while connecting: the connection is not taken, the session of the old instance is not bound to it */
static void t_connect_race(void)
{
	struct ap_session *ses;

	reset();
	ses = new_session(5);
	fake.on_connect = replace_socket;
	CHECK(rd(ses, NULL, NULL) == -EAGAIN);
	CHECK(fake.disconnect_calls == 1);

	fake.on_connect = NULL;
	usleep(BACKOFF_WAIT_US);
	CHECK(rd(ses, NULL, NULL) == -ENODEV);
}

/* a chmod or chown of the socket is not a restart */
static void t_chmod_not_a_restart(void)
{
	struct ap_session *ses;
	uint64_t rx;

	reset();
	fake_set_counters(5, 10, 100, 10, 100);
	ses = new_session(5);
	CHECK(rd(ses, &rx, NULL) == 0 && rx == 10);
	CHECK(chmod(VPPSTATS_SOCKET, 0600) == 0);
	fake_set_counters(5, 20, 200, 20, 200);
	CHECK(rd(ses, &rx, NULL) == 0 && rx == 20);
	CHECK(warnings == 0);
}

/*
 * VPP bumps the epoch of the segment for every interface it creates, the entries
 * of the session stay where they were. The heartbeat is only given if the client
 * knows the epoch, so a read must mark it as known. A VPP that freezes after that
 * is found by its heartbeat (VPPSTATS_STALL_SEC is 2 s in the test build).
 */
static void t_stall_after_epoch_change(void)
{
	struct ap_session *ses;
	uint64_t rx;

	reset();
	fake_set_counters(5, 10, 100, 10, 100);
	ses = new_session(5);
	CHECK(rd(ses, &rx, NULL) == 0 && rx == 10);

	fake.epoch += 7;
	CHECK(rd(ses, &rx, NULL) == 0);
	CHECK(rd(ses, &rx, NULL) == 0);

	/* frozen: reads still work, nothing moves */
	fake.hb_frozen = 1;
	CHECK(rd(ses, &rx, NULL) == 0);
	sleep(3);
	CHECK(rd(ses, &rx, NULL) == -ENODEV);
}

/* a heartbeat that moves is no stall, also with a changing epoch */
static void t_no_stall_while_beating(void)
{
	struct ap_session *ses;
	int i;

	reset();
	ses = new_session(5);
	for (i = 0; i < 5; i++) {
		fake.epoch += 3;
		CHECK(rd(ses, NULL, NULL) == 0);
		sleep(1);
	}
	CHECK(warnings == 0);
}

/* the stats socket hands out its descriptor: connecting works */
static void t_probe_answers(void)
{
	struct ap_session *ses;
	long t;

	reset();
	t = now_ms();
	CHECK(vppstats_probe(VPPSTATS_SOCKET) == 0);
	CHECK(now_ms() - t < 80);
	ses = new_session(5);
	CHECK(rd(ses, NULL, NULL) == 0);
	CHECK(fake.connect_calls == 1);
}

/* a VPP that accepts and says nothing: the library is not used, the wait is limited */
static void t_probe_stuck_vpp(void)
{
	struct ap_session *ses;
	long t;

	reset();
	ses = new_session(5);
	srv_hang = 1;
	t = now_ms();
	CHECK(vppstats_probe(VPPSTATS_SOCKET) == -1);
	t = now_ms() - t;
	printf("  probe took %ld ms\n", t);
	CHECK(t >= 90 && t < 250);

	t = now_ms();
	CHECK(rd(ses, NULL, NULL) == -EAGAIN);
	t = now_ms() - t;
	printf("  read took %ld ms\n", t);
	CHECK(t < 250);
	CHECK(fake.connect_calls == 0);

	/* VPP answers again after the backoff */
	srv_hang = 0;
	usleep(BACKOFF_WAIT_US);
	CHECK(rd(ses, NULL, NULL) == 0);
	CHECK(fake.connect_calls == 1);
}

/* no VPP: the socket is not there, or nobody listens */
static void t_probe_no_vpp(void)
{
	long t;
	int fd;

	reset();
	sock_remove();
	t = now_ms();
	CHECK(vppstats_probe(VPPSTATS_SOCKET) == -1);
	CHECK(now_ms() - t < 50);

	/* a file that is no socket */
	fd = open(VPPSTATS_SOCKET, O_CREAT | O_WRONLY, 0660);
	if (fd >= 0)
		close(fd);
	CHECK(vppstats_probe(VPPSTATS_SOCKET) == -1);
	unlink(VPPSTATS_SOCKET);
	CHECK(vppstats_probe("/nonexistent/dir/stats.sock") == -1);
}

/* closing the connection (no VPP use any more) is a clean slate, also for the backoff */
static void t_close_resets(void)
{
	struct ap_session *old, *young;

	reset();
	old = new_session(5);
	CHECK(rd(old, NULL, NULL) == 0);
	fake.stall = 1;
	CHECK(rd(old, NULL, NULL) == -EAGAIN);

	vppstats_close();
	fake.stall = 0;
	CHECK(rd(old, NULL, NULL) == -ENODEV);
	young = new_session(6);
	CHECK(rd(young, NULL, NULL) == 0);
}

static const struct {
	const char *name;
	void (*fn)(void);
} tests[] = {
	{ "delta_accumulation", t_delta_accumulation },
	{ "bind_at_first_read", t_bind_at_first_read },
	{ "counter_clear", t_counter_clear },
	{ "epoch_race_retry", t_epoch_race_retry },
	{ "unknown_index_eagain", t_unknown_index_eagain },
	{ "stall_budget", t_stall_budget },
	{ "lookup_budget", t_lookup_budget },
	{ "stall_backoff", t_stall_backoff },
	{ "final_read_ignores_backoff", t_final_read_ignores_backoff },
	{ "final_reads_share_backoff", t_final_reads_share_backoff },
	{ "frozen_total", t_frozen_total },
	{ "instance_replaced_bound", t_instance_replaced_bound },
	{ "instance_replaced_pending", t_instance_replaced_pending },
	{ "instance_replaced_during_creation", t_instance_replaced_during_creation },
	{ "no_socket_at_creation", t_no_socket_at_creation },
	{ "connect_failure_pending", t_connect_failure_pending },
	{ "connect_race", t_connect_race },
	{ "chmod_not_a_restart", t_chmod_not_a_restart },
	{ "close_resets", t_close_resets },
	{ "stall_after_epoch_change", t_stall_after_epoch_change },
	{ "no_stall_while_beating", t_no_stall_while_beating },
	{ "probe_answers", t_probe_answers },
	{ "probe_stuck_vpp", t_probe_stuck_vpp },
	{ "probe_no_vpp", t_probe_no_vpp },
};

int main(int argc, char **argv)
{
	size_t i;

	if (argc != 2) {
		fprintf(stderr, "usage: %s --list | NAME\n", argv[0]);
		return 2;
	}

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		if (!strcmp(argv[1], "--list"))
			printf("%s\n", tests[i].name);
		else if (!strcmp(argv[1], tests[i].name)) {
			tests[i].fn();
			printf("%s: %s\n", tests[i].name, failed ? "FAILED" : "ok");
			return failed;
		}
	}

	if (!strcmp(argv[1], "--list"))
		return 0;
	fprintf(stderr, "no test %s\n", argv[1]);
	return 2;
}
