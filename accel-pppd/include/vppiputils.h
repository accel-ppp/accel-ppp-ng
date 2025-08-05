/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
*/

#ifndef VPPIPUTILS_H
#define VPPIPUTILS_H

#include <stdint.h>
#include <netinet/in.h>

struct ap_session;
int vpp_iproute_add_del(struct ap_session *ses, int is_add, int ifindex, in_addr_t src, in_addr_t dst, in_addr_t gw, int proto, int mask, uint32_t prio);

int vpp_iproute_flush(struct ap_session *ses);

#endif /* VPPIPUTILS_H */