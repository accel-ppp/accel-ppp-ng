/* SPDX-License-Identifier: GPL-2.0-or-later */
/* A fake of the VPP stats client, see fake/vpp-api/client/stat_client.h */
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "vppinfra/vec.h"
#include "vpp-api/client/stat_client.h"
#include "fake_stat.h"

#define NTHREADS 2

struct fake_vec_hdr {
	unsigned len;
	unsigned pad[3];
};

stat_client_main_t stat_client_main;
struct fake_stat fake;

static vlib_stats_entry_t *dir;
static vlib_counter_t **rx_threads, **tx_threads;

static struct fake_vec_hdr *hdr(void *v)
{
	return (struct fake_vec_hdr *)v - 1;
}

void *fake_vec_grow(void *v, unsigned elem)
{
	unsigned len = v ? hdr(v)->len : 0;
	struct fake_vec_hdr *h = realloc(v ? hdr(v) : NULL, sizeof(*h) + (size_t)(len + 1) * elem);

	h->len = len + 1;
	return h + 1;
}

unsigned fake_vec_len(void *v)
{
	return v ? hdr(v)->len : 0;
}

void fake_vec_free(void *v)
{
	if (v)
		free(hdr(v));
}

int stat_segment_vec_len(void *v)
{
	return fake_vec_len(v);
}

static vlib_counter_t *new_counters(void)
{
	vlib_counter_t *c = NULL;
	int i;

	for (i = 0; i < FAKE_IFACES; i++) {
		c = fake_vec_grow(c, sizeof(*c));
		c[i] = (vlib_counter_t){ 0, 0 };
	}
	return c;
}

static vlib_counter_t **new_threads(void)
{
	vlib_counter_t **t = NULL;
	int i;

	for (i = 0; i < NTHREADS; i++) {
		t = fake_vec_grow(t, sizeof(*t));
		t[i] = new_counters();
	}
	return t;
}

static void free_threads(vlib_counter_t **t)
{
	int i;

	for (i = 0; t && i < (int)fake_vec_len(t); i++)
		fake_vec_free(t[i]);
	fake_vec_free(t);
}

void fake_reset(void)
{
	free_threads(rx_threads);
	free_threads(tx_threads);
	fake_vec_free(dir);
	dir = NULL;

	rx_threads = new_threads();
	tx_threads = new_threads();
	dir = fake_vec_grow(dir, sizeof(*dir));
	dir[0] = (vlib_stats_entry_t){ "/if/rx", STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED, rx_threads };
	dir = fake_vec_grow(dir, sizeof(*dir));
	dir[1] = (vlib_stats_entry_t){ "/if/tx", STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED, tx_threads };

	memset(&fake, 0, sizeof(fake));
	fake.connect_ok = 1;
	memset(&stat_client_main, 0, sizeof(stat_client_main));
}

void fake_set_counters(uint32_t idx, uint64_t rxp, uint64_t rxb, uint64_t txp, uint64_t txb)
{
	rx_threads[0][idx] = (vlib_counter_t){ rxp / 2, rxb / 2 };
	rx_threads[1][idx] = (vlib_counter_t){ rxp - rxp / 2, rxb - rxb / 2 };
	tx_threads[0][idx] = (vlib_counter_t){ txp / 2, txb / 2 };
	tx_threads[1][idx] = (vlib_counter_t){ txp - txp / 2, txb - txb / 2 };
}

/* what a wait for a segment that is being updated does: run into the timeout */
static void wait_timeout(const stat_client_main_t *sm)
{
	struct timespec ts = { sm->timeout / 1000000000ULL, sm->timeout % 1000000000ULL };

	nanosleep(&ts, NULL);
}

int stat_segment_connect(const char *socket_name)
{
	(void)socket_name;
	fake.connect_calls++;
	if (fake.on_connect)
		fake.on_connect();
	return fake.connect_ok ? 0 : -1;
}

void stat_segment_disconnect(void)
{
	fake.disconnect_calls++;
}

void stat_segment_set_timeout(uint64_t timeout)
{
	stat_client_main.timeout = timeout;
}

uint32_t *stat_segment_ls(uint8_t **patterns)
{
	uint32_t *ret = NULL;
	const char *p = (const char *)patterns[0];

	fake.ls_calls++;
	if (fake.stall) {
		wait_timeout(&stat_client_main);
		return NULL;
	}
	/* like the library: a listing marks the directory as known */
	stat_client_main.current_epoch = fake.epoch;

	ret = fake_vec_grow(ret, sizeof(*ret));
	ret[0] = !strcmp(p, "^/if/rx$") ? 0 : 1;
	return ret;
}

int stat_segment_access_start(stat_segment_access_t *sa, stat_client_main_t *sm)
{
	fake.access_calls++;
	sa->epoch = fake.epoch;
	if (fake.stall) {
		wait_timeout(sm);
		return -1;
	}
	sm->directory_vector = dir;
	return 0;
}

bool stat_segment_access_end(stat_segment_access_t *sa, stat_client_main_t *sm)
{
	(void)sa;
	(void)sm;
	if (fake.epoch_fail > 0) {
		fake.epoch_fail--;
		return false;
	}
	return true;
}

void *stat_segment_adjust(stat_client_main_t *sm, void *data)
{
	(void)sm;
	return data;
}

/* like the library: no heartbeat (0) if the directory is not the one the client knows */
double stat_segment_heartbeat(void)
{
	static double hb;

	if (fake.epoch != stat_client_main.current_epoch)
		return 0;
	if (!fake.hb_frozen)
		hb++;
	return hb ? hb : 1;
}
