/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
*/

#ifndef VPPUTILS_H
#define VPPUTILS_H

struct vapi_ctx_s;
struct vapi_ctx_s * vpp_get_vapi();

void vpp_lock();
void vpp_unlock();

/* export symbols */
void vpp_get();
void vpp_put();

struct vpp_handler_t {
	struct list_head entry;
	void (*on_vpp_connection_lost)(struct vpp_handler_t *);
};

void vpp_register_handler(struct vpp_handler_t *h);
void vpp_unregister_handler(struct vpp_handler_t *h);

#endif /* VPPUTILS_H */
