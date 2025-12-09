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

	struct list_head vpp_handlers;
} vpp_connect;

const char vpp_app_name[] = "accel-vpp";

static void vpppoe_connect_to_vpp()
{
	vpp_connect.vapi = NULL;
	vapi_error_e verr = vapi_ctx_alloc(&vpp_connect.vapi);

	if (verr != VAPI_OK || vpp_connect.vapi == NULL) {
		vpp_connect.vapi = NULL;
		return;
	}

	verr = vapi_connect_ex(vpp_connect.vapi, vpp_app_name, NULL, sc_vpp_queue_size, sc_vpp_queue_size, VAPI_MODE_BLOCKING, true, true);
	if (verr != VAPI_OK) {
		vapi_ctx_free(vpp_connect.vapi);
		vpp_connect.vapi = NULL;
		return;
	}
}

void vpppoe_disconnect_from_vpp()
{
	if (vpp_connect.vapi != NULL) {
		vapi_disconnect(vpp_connect.vapi);
		vapi_ctx_free(vpp_connect.vapi);
		vpp_connect.vapi = NULL;
	}
}

struct vapi_ctx_s * vpp_get_vapi() {
	if (vpp_connect.vapi == NULL && __sync_fetch_and_and(&vpp_connect.rfcounter, 1)) {
		vpppoe_connect_to_vpp();
	}
	return vpp_connect.vapi;
}

void vpp_lock() {
	pthread_mutex_lock(&vpp_connect.lock_vpp);
}

void vpp_unlock() {
	pthread_mutex_unlock(&vpp_connect.lock_vpp);
}

int vpp_get()
{
	vpp_lock();
	int rfc = __sync_fetch_and_add(&vpp_connect.rfcounter, 1);
	if (!rfc)
		vpppoe_connect_to_vpp();
	vpp_unlock();

	return 0;
}

void vpp_put()
{
	vpp_lock();
	int rfc = __sync_sub_and_fetch(&vpp_connect.rfcounter, 1);
	if (!rfc)
		vpppoe_disconnect_from_vpp();
	vpp_unlock();
}

void vpp_check_error(vapi_error_e err)
{
	if (vpp_connect.vapi && err >= VAPI_ECON_FAIL) {
		vpppoe_disconnect_from_vpp();
	}
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
	pthread_mutex_init(&vpp_connect.lock_vpp, NULL);
	INIT_LIST_HEAD(&vpp_connect.vpp_handlers);

	vpppoe_load_config();

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)vpppoe_load_config);
}

DEFINE_INIT(20, vpppoe_init);