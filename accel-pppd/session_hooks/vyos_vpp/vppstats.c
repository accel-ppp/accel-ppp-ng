/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Per-interface counters of VPP-terminated sessions. They do not exist in
 * the kernel, so they are read from the VPP stats segment instead of netlink.
 */

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
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

struct vppstats_counter {
	uint64_t packets;
	uint64_t bytes;
};

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int connected;
static struct timespec snap_ts;
static struct vppstats_counter *snap_rx, *snap_tx;
static uint32_t snap_len;

static void snapshot_free(void)
{
	free(snap_rx);
	free(snap_tx);
	snap_rx = snap_tx = NULL;
	snap_len = 0;
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

static int snapshot_refresh(void)
{
	stat_segment_data_t *res;
	u8 **patterns = NULL;
	u32 *dir;
	uint32_t len = 0;
	int i, ret = -1;

	if (!connected) {
		if (stat_segment_connect(VPPSTATS_SOCKET))
			return -1;
		connected = 1;
	}

	vec_add1(patterns, (u8 *)"/if/rx");
	vec_add1(patterns, (u8 *)"/if/tx");
	dir = stat_segment_ls(patterns);
	vec_free(patterns);
	if (!dir)
		goto disconnect;

	res = stat_segment_dump(dir);
	vec_free(dir);
	if (!res)
		goto disconnect;

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
		ret = -1;
		goto disconnect;
	}

	snap_len = len;
	clock_gettime(CLOCK_MONOTONIC, &snap_ts);
	return 0;

disconnect:
	/* VPP may have been restarted, reconnect on the next call */
	stat_segment_disconnect();
	connected = 0;
	return ret;
}

int vppstats_read_stats(struct ap_session *ses, struct rtnl_link_stats64 *stats)
{
	struct vpphook_private_data_t *pd = vpphook_get_pd(ses);
	struct timespec now;
	uint32_t idx;
	int ret = -1;

	/* sw_if_index 0 is local0, a session interface is never 0 */
	if (!pd || !pd->vpp_sw_if_index)
		return -1;
	idx = pd->vpp_sw_if_index;

	pthread_mutex_lock(&lock);

	clock_gettime(CLOCK_MONOTONIC, &now);
	/* a session created after the last snapshot is not in it, refresh then too */
	if (!snap_rx || idx >= snap_len || now.tv_sec - snap_ts.tv_sec >= VPPSTATS_CACHE_SEC) {
		if (snapshot_refresh() || idx >= snap_len)
			goto out;
	}

	memset(stats, 0, sizeof(*stats));
	stats->rx_packets = snap_rx[idx].packets;
	stats->rx_bytes = snap_rx[idx].bytes;
	stats->tx_packets = snap_tx[idx].packets;
	stats->tx_bytes = snap_tx[idx].bytes;
	ret = 0;
out:
	pthread_mutex_unlock(&lock);
	return ret;
}

void vppstats_close(void)
{
	pthread_mutex_lock(&lock);
	snapshot_free();
	if (connected) {
		stat_segment_disconnect();
		connected = 0;
	}
	pthread_mutex_unlock(&lock);
}
