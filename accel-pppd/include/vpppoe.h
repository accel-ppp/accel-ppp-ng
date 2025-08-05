/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
*/

#ifndef VPPPOE_H
#define VPPPOE_H

#include <stdint.h>
#include <netinet/in.h>

int vpppoe_sync_add_pppoe_interface(uint8_t *client_mac, in_addr_t *client_ip, uint16_t session_id, uint32_t *sw_ifindex);
int vpppoe_sync_del_pppoe_interface(uint8_t *client_mac, uint16_t session_id);
int vpppoe_set_feature(uint32_t ifindex, int is_enabled, const char *feature, const char *arc);

#endif /* VPPPOE_H */