/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
*/

#include <vapi/ip.api.vapi.h>

#include "ap_session.h"
#include "triton.h"
#include "vpputils.h"

#include "vppiputils.h"

#include <stdio.h>

DEFINE_VAPI_MSG_IDS_IP_API_JSON

struct vpp_route_t {
	struct list_head entry;
	in_addr_t dst;
	int mask;
};

static vapi_error_e vpp_ip_ro_cb(struct vapi_ctx_s *ctx,
								void *callback_ctx,
 								vapi_error_e rv,
								bool is_last,
								vapi_payload_ip_route_add_del_reply *reply)
{
	return VAPI_OK;
}

__export int vpp_iproute_add_del(struct ap_session *ses, int is_add, int ifindex, in_addr_t src,
								 in_addr_t dst, in_addr_t gw, int proto, int mask, uint32_t prio)
{
	vapi_msg_ip_route_add_del *req = vapi_alloc_ip_route_add_del(vpp_get_vapi(), 1);

	req->payload.is_add = is_add;
	req->payload.is_multipath = 0;
	req->payload.route.prefix.address.af = ADDRESS_IP4;
	memcpy(req->payload.route.prefix.address.un.ip4, &dst, sizeof(dst));
	req->payload.route.prefix.len = mask;
	req->payload.route.paths[0].sw_if_index = ifindex;

	vpp_lock();
	vapi_ip_route_add_del(vpp_get_vapi(), req, vpp_ip_ro_cb, NULL);
	vpp_unlock();

	if (is_add) {
		struct vpp_route_t *saved_route = (struct vpp_route_t *)malloc(sizeof(*saved_route));
		memcpy(&saved_route->dst, &dst, sizeof(dst));
		saved_route->mask = mask;
		list_add_tail(&saved_route->entry, &ses->vpp_routes);
	}

	return 0;
}

__export int vpp_iproute_flush(struct ap_session *ses)
{
	struct list_head *pos, *n;

	list_for_each_safe(pos, n, &ses->vpp_routes) {
		struct vpp_route_t *saved_route = list_entry(pos, typeof(*saved_route), entry);
		vpp_iproute_add_del(ses, 0, ses->vpp_sw_if_index, 0, saved_route->dst, 0, 0, saved_route->mask, 0);
		list_del(&saved_route->entry);
		free(saved_route);
	}

	return 0;
}
