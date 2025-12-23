/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
*/

#include <vapi/ip.api.vapi.h>

#include "ap_session.h"
#include "triton.h"
#include "vpputils.h"
#include "vpphooks.h"

#include "vppiputils.h"

DEFINE_VAPI_MSG_IDS_IP_API_JSON

extern void vpp_check_error(vapi_error_e err);

struct vpp_route_t {
	struct list_head entry;

	int af;

	union {
		struct {
			in_addr_t dst;
			int mask;
		} ip4;

		struct {
			struct in6_addr dst;
			int preffix;
		} ip6;
	} un;
};

static void vpp_iproute_save(struct ap_session *ses, in_addr_t dst, int mask)
{
	struct vpp_route_t *saved_route = (struct vpp_route_t *)malloc(sizeof(*saved_route));
	struct vpphook_private_data_t *vpphook_data = vpphook_get_pd(ses);
	saved_route->af = AF_INET;
	memcpy(&saved_route->un.ip4.dst, &dst, sizeof(dst));
	saved_route->un.ip4.mask = mask;
	list_add_tail(&saved_route->entry, &vpphook_data->vpp_routes);
}

static void vpp_iproute_del_saved(struct ap_session *ses, in_addr_t dst, int mask)
{
	struct list_head *pos, *n;
	struct vpphook_private_data_t *vpphook_data = vpphook_get_pd(ses);

	list_for_each_safe(pos, n, &vpphook_data->vpp_routes) {
		struct vpp_route_t *saved_route = list_entry(pos, typeof(*saved_route), entry);

		if (saved_route->af == AF_INET && saved_route->un.ip4.dst == dst && saved_route->un.ip4.mask == mask) {
			list_del(&saved_route->entry);
			free(saved_route);
		}
	}
}

static void vpp_ip6route_save(struct ap_session *ses, const struct in6_addr *dst, int pref_len)
{
	struct vpp_route_t *saved_route = (struct vpp_route_t *)malloc(sizeof(*saved_route));
	struct vpphook_private_data_t *vpphook_data = vpphook_get_pd(ses);
	saved_route->af = AF_INET6;
	memcpy(&saved_route->un.ip6.dst, dst, sizeof(*dst));
	saved_route->un.ip6.preffix = pref_len;
	list_add_tail(&saved_route->entry, &vpphook_data->vpp_routes);
}

static void vpp_ip6route_del_saved(struct ap_session *ses, const struct in6_addr *dst, int pref_len)
{
	struct list_head *pos, *n;
	struct vpphook_private_data_t *vpphook_data = vpphook_get_pd(ses);

	list_for_each_safe(pos, n, &vpphook_data->vpp_routes) {
		struct vpp_route_t *saved_route = list_entry(pos, typeof(*saved_route), entry);

		if (saved_route->af == AF_INET6 && !memcmp(saved_route->un.ip6.dst.s6_addr, dst->s6_addr, sizeof(dst->s6_addr)) && saved_route->un.ip6.preffix == pref_len) {
			list_del(&saved_route->entry);
			free(saved_route);
		}
	}
}

static vapi_error_e vpp_ip_ro_cb(struct vapi_ctx_s *ctx,
								 void *callback_ctx,
								 vapi_error_e rv,
								 bool is_last,
								 vapi_payload_ip_route_add_del_reply *reply)
{
	return rv;
}

static int vpp_iproute(int is_add, int ifindex,
								 in_addr_t dst, int mask)
{
	vapi_error_e err = -1;
	struct vapi_ctx_s *ctx;

	vpp_lock();

	ctx = vpp_get_vapi();
	if (ctx == NULL) {
		goto exit;
	}

	vapi_msg_ip_route_add_del *req = vapi_alloc_ip_route_add_del(ctx, 1);
	if (req == NULL) {
		goto exit;
	}

	req->payload.is_add = is_add;
	req->payload.is_multipath = 0;
	req->payload.route.prefix.address.af = ADDRESS_IP4;
	memcpy(req->payload.route.prefix.address.un.ip4, &dst, sizeof(dst));
	req->payload.route.prefix.len = mask;
	req->payload.route.paths[0].sw_if_index = ifindex;

	err = vapi_ip_route_add_del(ctx, req, vpp_ip_ro_cb, NULL);
	vpp_check_error(err);

exit:
	vpp_unlock();
	return err;
}

int vpp_iproute_add_del(struct ap_session *ses, int is_add, int ifindex, in_addr_t src,
								 in_addr_t dst, in_addr_t gw, int proto, int mask, uint32_t prio)
{
	int ret = vpp_iproute(is_add, ifindex, dst, mask);

	if (is_add)
		vpp_iproute_save(ses, dst, mask);
	else
		vpp_iproute_del_saved(ses, dst, mask);

	return ret;
}

static int vpp_ip6route(int is_add, int ifindex, const struct in6_addr *dst, int pref_len)
{
	vapi_error_e err = -1;;
	struct vapi_ctx_s *ctx;

	vpp_lock();

	ctx = vpp_get_vapi();
	if (ctx == NULL) {
		goto exit;
	}

	vapi_msg_ip_route_add_del *req = vapi_alloc_ip_route_add_del(ctx, 1);
	if (req == NULL) {
		goto exit;
	}

	req->payload.is_add = is_add;
	req->payload.is_multipath = 0;
	req->payload.route.prefix.address.af = ADDRESS_IP6;
	memcpy(req->payload.route.prefix.address.un.ip6, dst, sizeof(*dst));
	req->payload.route.prefix.len = pref_len;
	req->payload.route.paths[0].sw_if_index = ifindex;

	err = vapi_ip_route_add_del(ctx, req, vpp_ip_ro_cb, NULL);
	vpp_check_error(err);

exit:
	vpp_unlock();
	return err;
}

int vpp_ip6route_add_del(struct ap_session *ses, int is_add, int ifindex, const struct in6_addr *dst, int pref_len, const struct in6_addr *gw, int proto, uint32_t prio)
{
	int ret = vpp_ip6route(is_add, ifindex, dst, pref_len);

	if (is_add)
		vpp_ip6route_save(ses, dst, pref_len);
	else
		vpp_ip6route_del_saved(ses, dst, pref_len);

	return ret;
}

int vpp_iproute_flush(struct ap_session *ses)
{
	struct list_head *pos, *n;
	struct vpphook_private_data_t *vpphook_data = vpphook_get_pd(ses);

	list_for_each_safe(pos, n, &vpphook_data->vpp_routes) {
		struct vpp_route_t *saved_route = list_entry(pos, typeof(*saved_route), entry);

		if (saved_route->af == AF_INET)
			vpp_iproute(0, vpphook_data->vpp_sw_if_index, saved_route->un.ip4.dst, saved_route->un.ip4.mask);
		else if (saved_route->af == AF_INET6)
			vpp_ip6route(0, vpphook_data->vpp_sw_if_index, &saved_route->un.ip6.dst, saved_route->un.ip6.preffix);

		list_del(&saved_route->entry);
		free(saved_route);
	}

	return 0;
}
