/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef VPPSTATS_H
#define VPPSTATS_H

#include <stdint.h>

struct ap_session;
struct rtnl_link_stats64;

struct vppstats_counts {
	uint64_t rx_packets, rx_bytes;
	uint64_t tx_packets, tx_bytes;
};

/*
 * Per-session state. A VPP sw_if_index is reused after a session is deleted
 * and says nothing about which session or which VPP instance it belongs to,
 * so the identity of a session is kept here, next to the counters.
 */
struct vppstats_session {
	uint8_t base_valid;	/* base was taken from a fresh read after the interface was created */
	uint8_t frozen;		/* final sample, the interface is gone (or about to be) */
	uint32_t inst_gen;	/* VPP instance generation the base belongs to */
	struct vppstats_counts base;	/* raw counters when the session started */
	struct vppstats_counts last;	/* last good value relative to base, also the frozen one */
};

/*
 * ap_session_hooks_t::read_stats, counters come from the VPP stats segment.
 * 0 - OK, -EAGAIN - stats temporarily unavailable (session is not lost),
 * other - the session counters are gone (VPP instance changed or lost)
 */
int vppstats_read_stats(struct ap_session *ses, struct rtnl_link_stats64 *stats);

/* the VPP interface of the session was just created, drop the cached snapshot */
void vppstats_session_created(struct ap_session *ses);

/* take the final sample and freeze it, call before the VPP interface is deleted */
void vppstats_session_freeze(struct ap_session *ses);

/* drop the stats segment connection and the cached snapshot */
void vppstats_close(void);

#endif /* VPPSTATS_H */
