/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
*/

#include <vapi/vapi.h>
#include <vapi/vpe.api.vapi.h>

#include <pthread.h>

#include "triton.h"
#include "events.h"

#include "vpputils.h"

int sc_vpp_queue_size = 1024;

struct vpp_connect_t
{
	vapi_ctx_t vapi;
	int rfcounter;
	pthread_mutex_t lock_vpp;
} vpp_connect;

const char vpp_app_name[] = "accel-vpp";

static void vpppoe_connect_to_vpp()
{
	vapi_error_e verr = vapi_ctx_alloc(&vpp_connect.vapi);

	if (verr != VAPI_OK) {
		vpp_connect.vapi = NULL;
		return;
	}

	verr = vapi_connect_ex(vpp_connect.vapi, vpp_app_name, NULL, sc_vpp_queue_size, sc_vpp_queue_size, VAPI_MODE_BLOCKING, true, true);
	if (verr != VAPI_OK) {
		vapi_ctx_free(vpp_connect.vapi);
		vpp_connect.vapi = NULL;
		return;
	}

	pthread_mutex_init(&vpp_connect.lock_vpp, NULL);
}

void vpppoe_disconnect_from_vpp()
{
	pthread_mutex_destroy(&vpp_connect.lock_vpp);
	vapi_disconnect(vpp_connect.vapi);
	vapi_ctx_free(vpp_connect.vapi);
	vpp_connect.vapi = NULL;
}

struct vapi_ctx_s * vpp_get_vapi() {
	return vpp_connect.vapi;
}

void vpp_lock() {
	pthread_mutex_lock(&vpp_connect.lock_vpp);
}

void vpp_unlock() {
	pthread_mutex_unlock(&vpp_connect.lock_vpp);
}

void __export vpp_get()
{
	int rfc = __sync_fetch_and_add(&vpp_connect.rfcounter, 1);
	if (!rfc)
		vpppoe_connect_to_vpp();
}

void __export vpp_put()
{
	int rfc = __sync_sub_and_fetch(&vpp_connect.rfcounter, 1);
	if (!rfc)
		vpppoe_disconnect_from_vpp();
}


static void vpppoe_load_config(void)
{
	char *opt;

	opt = conf_get_opt("vpp", "queue-size");
	if (opt)
		sc_vpp_queue_size = atoi(opt);      
}

static void vpppoe_init()
{
	memset(&vpp_connect, 0, sizeof(vpp_connect));

	vpppoe_load_config();

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)vpppoe_load_config);
}

DEFINE_INIT(20, vpppoe_init);