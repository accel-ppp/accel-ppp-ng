/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef VPPSTATS_H
#define VPPSTATS_H

struct ap_session;
struct rtnl_link_stats64;

/* ap_session_hooks_t::read_stats, counters come from the VPP stats segment */
int vppstats_read_stats(struct ap_session *ses, struct rtnl_link_stats64 *stats);

/* drop the stats segment connection and the cached snapshot */
void vppstats_close(void);

#endif /* VPPSTATS_H */
