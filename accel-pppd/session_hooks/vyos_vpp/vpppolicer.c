/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
 */

#include <vapi/vapi.h>
#include <vapi/vpe.api.vapi.h>
#include <vapi/policer.api.vapi.h>

#include <stdio.h>

#include "ap_session.h"
#include "triton.h"
#include "events.h"
#include "vpputils.h"
#include "vpppoe.h"
#include "vpphooks.h"

#include "vpppolicer.h"

DEFINE_VAPI_MSG_IDS_POLICER_API_JSON

#define POLICER_NAME_MAX_LEN 64

extern void vpp_check_error(vapi_error_e err);

static uint32_t s_vpp_policer_type = SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_2698;
static double s_cir_factor = 0.8;
static double s_cb_factor = 1;
static double s_eir_factor = 1;
static double s_eb_factor = 0.2;
static uint32_t s_conform_action = SSE2_QOS_ACTION_API_TRANSMIT;
static uint32_t s_exceed_action = SSE2_QOS_ACTION_API_TRANSMIT;
static uint32_t s_violate_action = SSE2_QOS_ACTION_API_DROP;

static vapi_error_e vpppolicer_set_input_callback(struct vapi_ctx_s *ctx,
												void *callback_ctx,
												vapi_error_e rv,
												bool is_last,
												vapi_payload_policer_input_reply *reply)
{
	return rv;
}

int vpppolicer_set_input(int is_add, uint32_t ifindex, const char *policer_name)
{
	vapi_error_e err = -1;
	struct vapi_ctx_s *ctx;

	vpp_lock();

	ctx = vpp_get_vapi();
	if (ctx == NULL) {
		goto exit;
	}

	vapi_msg_policer_input *req = vapi_alloc_policer_input(ctx);
	if (req == NULL) {
		goto exit;
	}

	req->payload.apply = is_add;
	strncpy((char *)req->payload.name, policer_name, sizeof(req->payload.name) - 1);
	req->payload.name[sizeof(req->payload.name) - 1] = 0;
	req->payload.sw_if_index = ifindex;

	err = vapi_policer_input(ctx, req, vpppolicer_set_input_callback, NULL);
	vpp_check_error(err);

exit:
	vpp_unlock();
	return err;
}

static vapi_error_e vpppolicer_set_output_callback(struct vapi_ctx_s *ctx,
												void *callback_ctx,
												vapi_error_e rv,
												bool is_last,
												vapi_payload_policer_output_reply *reply)
{
	return rv;
}

int vpppolicer_set_output(int is_add, uint32_t ifindex, const char *policer_name)
{
	vapi_error_e err = -1;
	struct vapi_ctx_s *ctx;

	vpp_lock();

	ctx = vpp_get_vapi();
	if (ctx == NULL) {
		goto exit;
	}

	vapi_msg_policer_output *req = vapi_alloc_policer_output(ctx);
	if (req == NULL) {
		goto exit;
	}

	req->payload.apply = is_add;
	strncpy((char *)req->payload.name, policer_name, sizeof(req->payload.name) - 1);
	req->payload.name[sizeof(req->payload.name) - 1] = 0;
	req->payload.sw_if_index = ifindex;

	err = vapi_policer_output(ctx, req, vpppolicer_set_output_callback, NULL);
	vpp_check_error(err);

exit:
	vpp_unlock();
	return err;
}

static vapi_error_e vpppolicer_add_del_callback(struct vapi_ctx_s *ctx,
												void *callback_ctx,
												vapi_error_e rv,
												bool is_last,
												vapi_payload_policer_add_del_reply *reply)
{
	return rv;
}

static int vpppolicer_add_del(int is_add, const char *policer_name, uint32_t cir_kbits, uint64_t cb_bits)
{
	vapi_error_e err = -1;
	struct vapi_ctx_s *ctx;

	vpp_lock();

	ctx = vpp_get_vapi();
	if (ctx == NULL) {
		goto exit;
	}

	vapi_msg_policer_add_del *req = vapi_alloc_policer_add_del(ctx);
	if (req == NULL) {
		goto exit;
	}

	req->payload.is_add = is_add;
	strncpy((char *)req->payload.name, policer_name, sizeof(req->payload.name) - 1);
	req->payload.name[sizeof(req->payload.name) - 1] = 0;

	req->payload.cir = cir_kbits * s_cir_factor;
	req->payload.cb = cb_bits * s_cb_factor;
	req->payload.eir = cir_kbits * s_eir_factor;
	req->payload.eb = cb_bits * s_eb_factor;

	req->payload.rate_type = SSE2_QOS_RATE_API_KBPS;
	req->payload.round_type = SSE2_QOS_ROUND_API_TO_CLOSEST;
	req->payload.type = s_vpp_policer_type;

	req->payload.conform_action.type = s_conform_action;
	req->payload.exceed_action.type = s_exceed_action;
	req->payload.violate_action.type = s_violate_action;

	req->payload.color_aware = 0;

	err = vapi_policer_add_del(ctx, req, vpppolicer_add_del_callback, NULL);
	vpp_check_error(err);

exit:
	vpp_unlock();
	return err;
}

static void vpppolicer_generate_name(char *name, size_t size, struct ap_session *ses, uint32_t rate, uint64_t burst, int is_up)
{
	snprintf(name, size, "vyos_%d_%d_%ld_%s", vpphook_get_pd(ses)->vpp_sw_if_index, rate, burst, is_up ? "up" : "down");
}

int vpppolicer_install_limiter(struct ap_session *ses, int down_speed, int down_burst, int up_speed, int up_burst)
{
	int ret = 0;
	char policer_input[POLICER_NAME_MAX_LEN] = {};
	char policer_output[POLICER_NAME_MAX_LEN] = {};
	struct vpphook_private_data_t *vpphook_data = vpphook_get_pd(ses);

	/* convert rate to kbits/s and burst to bits */
	down_speed = down_speed * 8 / 1000;
	down_burst = down_burst * 8;
	up_speed = up_speed * 8 / 1000;
	up_burst = up_burst * 8;

	/* Remove previously installed limiter, if exists */
	vpppolicer_remove_limiter(ses);

	if (down_speed) {
		vpppolicer_generate_name(policer_output, POLICER_NAME_MAX_LEN - 1, ses, down_speed, down_burst, 0);
		vpppolicer_add_del(1, policer_output, down_speed, down_burst);
		ret = vpppolicer_set_output(1, vpphook_data->vpp_sw_if_index, policer_output);
		if (ret) {
			vpppolicer_add_del(0, policer_output, down_speed, down_burst);
			goto exit;
		}

		vpphook_data->vpppolicer_down = down_speed;
		vpphook_data->vpppolicer_down_burst = down_burst;
	}

	if (up_speed) {
		vpppolicer_generate_name(policer_input, POLICER_NAME_MAX_LEN - 1, ses, up_speed, up_burst, 1);
		vpppolicer_add_del(1, policer_input, up_speed, up_burst);
		ret = vpppolicer_set_input(1, vpphook_data->vpp_sw_if_index, policer_input);
		if (ret) {
			vpppolicer_add_del(0, policer_input, up_speed, up_burst);
			if (down_speed) {
				vpppolicer_set_output(0, vpphook_data->vpp_sw_if_index, policer_output);
				vpppolicer_add_del(0, policer_output, down_speed, down_burst);
				vpphook_data->vpppolicer_down = 0;
				vpphook_data->vpppolicer_down_burst = 0;
			}
			goto exit;
		}

		vpppoe_set_feature(vpphook_data->vpp_sw_if_index, 1, "policer-input", "ip4-unicast");
		vpppoe_set_feature(vpphook_data->vpp_sw_if_index, 1, "policer-input", "ip6-unicast");
		vpppoe_set_feature(vpphook_data->vpp_sw_if_index, 1, "policer-input", "ip4-multicast");
		vpppoe_set_feature(vpphook_data->vpp_sw_if_index, 1, "policer-input", "ip6-multicast");

		vpphook_data->vpppolicer_up = up_speed;
		vpphook_data->vpppolicer_up_burst = up_burst;
	}

exit:
	return ret;
}

int vpppolicer_remove_limiter(struct ap_session *ses)
{
	int ret = 0;
	char policer_input[64] = {};
	char policer_output[64] = {};
	struct vpphook_private_data_t *vpphook_data = vpphook_get_pd(ses);

	if (vpphook_data->vpppolicer_down) {
		vpppolicer_generate_name(policer_output, POLICER_NAME_MAX_LEN - 1, ses, vpphook_data->vpppolicer_down, vpphook_data->vpppolicer_down_burst, 0);
		ret = vpppolicer_set_output(0, vpphook_data->vpp_sw_if_index, policer_output);
		if (ret)
			goto exit;
		vpppolicer_add_del(0, policer_output, vpphook_data->vpppolicer_down, vpphook_data->vpppolicer_down_burst);
		vpphook_data->vpppolicer_down = 0;
		vpphook_data->vpppolicer_down_burst = 0;
	}

	if (vpphook_data->vpppolicer_up) {
		vpppolicer_generate_name(policer_input, POLICER_NAME_MAX_LEN - 1, ses, vpphook_data->vpppolicer_up, vpphook_data->vpppolicer_up_burst, 1);
		ret = vpppolicer_set_input(0, vpphook_data->vpp_sw_if_index, policer_input);
		if (ret)
			goto exit;
		vpppolicer_add_del(0, policer_input, vpphook_data->vpppolicer_up, vpphook_data->vpppolicer_up_burst);

		vpppoe_set_feature(vpphook_data->vpp_sw_if_index, 0, "policer-input", "ip4-unicast");
		vpppoe_set_feature(vpphook_data->vpp_sw_if_index, 0, "policer-input", "ip6-unicast");
		vpppoe_set_feature(vpphook_data->vpp_sw_if_index, 0, "policer-input", "ip4-multicast");
		vpppoe_set_feature(vpphook_data->vpp_sw_if_index, 0, "policer-input", "ip6-multicast");

		vpphook_data->vpppolicer_up = 0;
		vpphook_data->vpppolicer_up_burst = 0;
	}

exit:
	return ret;
}

static uint32_t vpppolicer_parse_action(const char *opt)
{
	uint32_t ret = SSE2_QOS_ACTION_API_DROP;

	if (!strncmp(opt, "transmit", sizeof("transmit") - 1)) {
		ret = SSE2_QOS_ACTION_API_TRANSMIT;
	} /* TODO: add transmit and mark? */

	return ret;
}

static void vpppolicer_load_config(void)
{
	char *opt;

	opt = conf_get_opt("shaper", "vpp-policer-type");
	if (opt) {
		s_conform_action = SSE2_QOS_ACTION_API_TRANSMIT;
		s_exceed_action = SSE2_QOS_ACTION_API_DROP;
		s_violate_action = SSE2_QOS_ACTION_API_DROP;

		s_cir_factor = 1;
		s_cb_factor = 1;
		s_eir_factor = 0;
		s_eb_factor = 0;

		if (!strncmp(opt, "1r2c", sizeof("1r2c") - 1)) {
			s_vpp_policer_type = SSE2_QOS_POLICER_TYPE_API_1R2C;
		} else if (!strncmp(opt, "1r3c", sizeof("1r3c") - 1)) {
			s_vpp_policer_type = SSE2_QOS_POLICER_TYPE_API_1R3C_RFC_2697;
			s_cb_factor = 0.8;
			s_eb_factor = 0.2;
		} else if (!strncmp(opt, "2r3c", sizeof("2r3c") - 1)) {
			s_vpp_policer_type = SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_2698;
			s_cir_factor = 0.8;
			s_eir_factor = 1;
			s_eb_factor = 0.2;
			s_exceed_action = SSE2_QOS_ACTION_API_TRANSMIT;
		}
	}

	opt = conf_get_opt("shaper", "vpp-cir-factor");
	if (opt)
		s_cir_factor = atof(opt);

	opt = conf_get_opt("shaper", "vpp-cb-factor");
	if (opt)
		s_cb_factor = atof(opt);

	opt = conf_get_opt("shaper", "vpp-eir-factor");
	if (opt)
		s_eir_factor = atof(opt);

	opt = conf_get_opt("shaper", "vpp-eb-factor");
	if (opt)
		s_eb_factor = atof(opt);

	opt = conf_get_opt("shaper", "vpp-conform-action");
	if (opt)
		s_conform_action = vpppolicer_parse_action(opt);

	opt = conf_get_opt("shaper", "vpp-exceed-action");
	if (opt)
		s_exceed_action = vpppolicer_parse_action(opt);

	opt = conf_get_opt("shaper", "vpp-violate-action");
	if (opt)
		s_violate_action = vpppolicer_parse_action(opt);
}

static void vpppolicer_init()
{
	vpppolicer_load_config();

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)vpppolicer_load_config);
}

DEFINE_INIT(50, vpppolicer_init);
