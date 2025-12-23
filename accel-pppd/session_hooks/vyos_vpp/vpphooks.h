/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
 */

#ifndef VPPHOOKS_H
#define VPPHOOKS_H

#include <stdint.h>

#include "ap_session.h"

#include "list.h"

struct vpphook_private_data_t {
	struct ap_private pd;
	uint32_t vpp_sw_if_index;
	struct list_head vpp_routes;
	uint32_t vpppolicer_down;
	uint64_t vpppolicer_down_burst;
	uint32_t vpppolicer_up;
	uint64_t vpppolicer_up_burst;
};

struct vpphook_private_data_t *vpphook_get_pd(struct ap_session *ses);

#endif /* VPPHOOKS_H */