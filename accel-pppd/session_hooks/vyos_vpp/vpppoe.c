/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
 */

#include <vapi/vapi.h>
#include <vapi/vpe.api.vapi.h>
#include <vapi/pppoe.api.vapi.h>
#include <vapi/feature.api.vapi.h>
#include <vapi/interface.api.vapi.h>

#include <linux/if_ether.h>

#include <memory.h>
#include <stdio.h>

#include "triton.h"
#include "vpputils.h"
#include "vpppoe.h"

DEFINE_VAPI_MSG_IDS_VPE_API_JSON
DEFINE_VAPI_MSG_IDS_PPPOE_API_JSON
DEFINE_VAPI_MSG_IDS_FEATURE_API_JSON
DEFINE_VAPI_MSG_IDS_INTERFACE_API_JSON

extern void vpp_check_error(vapi_error_e err);

static vapi_error_e vpppoe_s_session_add_reply_callback(struct vapi_ctx_s *ctx,
														void *callback_ctx,
														vapi_error_e rv,
														bool is_last,
														vapi_payload_pppoe_add_del_session_reply *reply)
{
	uint32_t *sw_ifindex = (uint32_t *)callback_ctx;
	if (rv == VAPI_OK) {
		if (sw_ifindex) {
			*sw_ifindex = reply->sw_if_index;
		}
	}

	return rv;
}

int vpppoe_sync_add_pppoe_interface(uint8_t *client_mac, uint16_t session_id, uint32_t *sw_ifindex)
{
	vapi_error_e err = -1;
	struct vapi_ctx_s *ctx;

	vpp_lock();

	ctx = vpp_get_vapi();
	if (ctx == NULL) {
		goto exit;
	}

	vapi_msg_pppoe_add_del_session *req = vapi_alloc_pppoe_add_del_session(ctx);
	if (req == NULL) {
		goto exit;
	}

	req->payload.client_ip.af = ADDRESS_IP4;
	memcpy(req->payload.client_mac, client_mac, ETH_ALEN);

	req->payload.is_add = 1;
	req->payload.session_id = session_id;
	req->payload.disable_fib = 1;

	err = vapi_pppoe_add_del_session(ctx, req, vpppoe_s_session_add_reply_callback, sw_ifindex);
	vpp_check_error(err);

exit:
	vpp_unlock();
	return err;
}

static vapi_error_e vpppoe_s_session_del_reply_callback(struct vapi_ctx_s *ctx,
														void *callback_ctx,
														vapi_error_e rv,
														bool is_last,
														vapi_payload_pppoe_add_del_session_reply *reply)
{
	return rv;
}

int vpppoe_sync_del_pppoe_interface(uint8_t *client_mac, uint16_t session_id)
{
	vapi_error_e err = -1;
	struct vapi_ctx_s *ctx;

	vpp_lock();

	ctx = vpp_get_vapi();
	if (ctx == NULL) {
		goto exit;
	}

	vapi_msg_pppoe_add_del_session *req = vapi_alloc_pppoe_add_del_session(ctx);
	if (req == NULL) {
		goto exit;
	}

	req->payload.client_ip.af = ADDRESS_IP4;
	memcpy(req->payload.client_mac, client_mac, ETH_ALEN);

	req->payload.is_add = 0;
	req->payload.session_id = session_id;
	req->payload.disable_fib = 1;

	err = vapi_pppoe_add_del_session(ctx, req, vpppoe_s_session_del_reply_callback, NULL);
	vpp_check_error(err);

exit:
	vpp_unlock();
	return err;
}

static vapi_error_e vpppoe_set_feature_callback(struct vapi_ctx_s *ctx,
												void *callback_ctx,
												vapi_error_e rv,
												bool is_last,
												vapi_payload_feature_enable_disable_reply *reply)
{
	return rv;
}

int vpppoe_set_feature(uint32_t ifindex, int is_enabled, const char *feature, const char *arc)
{
	vapi_error_e err = -1;
	struct vapi_ctx_s *ctx;

	vpp_lock();

	ctx = vpp_get_vapi();
	if (ctx == NULL) {
		goto exit;
	}

	vapi_msg_feature_enable_disable *req = vapi_alloc_feature_enable_disable(ctx);
	if (req == NULL) {
		goto exit;
	}

	strncpy((char *)req->payload.feature_name, feature, 63);
	req->payload.feature_name[63] = 0;
	strncpy((char *)req->payload.arc_name, arc, 63);
	req->payload.arc_name[63] = 0;

	req->payload.sw_if_index = ifindex;
	req->payload.enable = is_enabled;

	err = vapi_feature_enable_disable(ctx, req, vpppoe_set_feature_callback, NULL);
	vpp_check_error(err);

exit:
	vpp_unlock();
	return err;
}

typedef struct vpppoe_dump_interface_name_ctx_t
{
	char *name;
	size_t size;
} vpppoe_dump_interface_name_ctx_t;

static vapi_error_e vpppoe_dump_interface_name_callback(struct vapi_ctx_s *ctx,
											void *callback_ctx,
											vapi_error_e rv,
											bool is_last,
											vapi_payload_sw_interface_details *reply)
{
	if (callback_ctx != NULL && reply != NULL && rv == VAPI_OK) {
		vpppoe_dump_interface_name_ctx_t *ctx = (vpppoe_dump_interface_name_ctx_t *)callback_ctx;
		strncpy(ctx->name, (const char *)reply->interface_name, ctx->size > 64 ? 64 : ctx->size);
		ctx->name[(ctx->size > 64 ? 64 : ctx->size) - 1] = 0;
	}

	return rv;
}

int vpppoe_dump_interface_name(uint32_t ifindex, char *name, size_t size)
{
	vapi_error_e err = -1;
	struct vapi_ctx_s *ctx;

	if (name == NULL || !size) {
		return -1;
	}

	vpp_lock();

	ctx = vpp_get_vapi();
	if (ctx == NULL) {
		goto exit;
	}

	/* Allocated in stack - works only with sync VPP client */
	vpppoe_dump_interface_name_ctx_t dump_ctx = {name, size};

	vapi_msg_sw_interface_dump *req = vapi_alloc_sw_interface_dump(ctx, 0);
	if (req == NULL) {
		goto exit;
	}

	req->payload.sw_if_index = ifindex;

	err = vapi_sw_interface_dump(ctx, req, vpppoe_dump_interface_name_callback, &dump_ctx);
	vpp_check_error(err);

exit:
	vpp_unlock();
	return err;
}