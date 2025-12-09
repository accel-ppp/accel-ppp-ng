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
int vpp_get();
void vpp_put();

#endif /* VPPUTILS_H */
