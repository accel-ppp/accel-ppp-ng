/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
 */

#include <linux/if_ether.h> /* ETH_P_ALL */
#include <string.h>

#include "triton.h"
#include "events.h"
#include "ap_session_hooks.h"

#include "ap_session.h"
#include "ppp.h"
#include "ipdb.h"
#include "memdebug.h"

#include "vpputils.h"
#include "vppiputils.h"
#include "vpppolicer.h"
#include "vpppoe.h"

#include "vpphooks.h"

/* NOTE: function from ctrl/pppoe plugin! */
void pppoe_get_session_mac_and_sid(struct ap_session *ses, uint8_t **mac, uint16_t *sid);

static void *pd_key;

struct vpphook_private_data_t *vpphook_get_pd(struct ap_session *ses)
{
	struct ap_private *pd;

	list_for_each_entry(pd, &ses->pd_list, entry) {
		if (pd->key == &pd_key)
			return container_of(pd, struct vpphook_private_data_t, pd);
	}

	return NULL;
}

int vpphook_session_hook_init(struct ap_session *ses)
{
	struct vpphook_private_data_t *pd = _malloc(sizeof(struct vpphook_private_data_t));
	if (pd == NULL)
		return -1;

	memset(pd, 0, sizeof(struct vpphook_private_data_t));
	pd->pd.key = &pd_key;

	INIT_LIST_HEAD(&pd->vpp_routes);

	list_add_tail(&pd->pd.entry, &ses->pd_list);

	return 0; /* return 0 is ok */
}

void vpphook_session_hook_deinit(struct ap_session *ses)
{
	struct vpphook_private_data_t *pd = vpphook_get_pd(ses);
	if (pd == NULL)
		return;

	list_del(&pd->pd.entry);
	_free(pd);
}

int vpphook_pppoe_create_vpp_session_interface(struct ap_session *ses)
{
	uint32_t ifindex = -1;
	int ret = 0;
	uint8_t *mac = NULL;
	uint16_t sid;

	pppoe_get_session_mac_and_sid(ses, &mac, &sid);

	ret = vpppoe_sync_add_pppoe_interface(mac, sid, &ifindex);
	if (ret) {
		return ret;
	}

	vpphook_get_pd(ses)->vpp_sw_if_index = ifindex;
	vpppoe_dump_interface_name(ifindex, ses->ifname, AP_IFNAME_LEN);

	if (ses->ipv4) {
		vpppoe_set_feature(ifindex, 0, "ip4-not-enabled", "ip4-unicast");
		vpp_iproute_add_del(ses, 1, ifindex, 0, ses->ipv4->peer_addr, 0, ETH_P_ALL, 32, 0);
	}

	if (ses->ipv6)
		vpppoe_set_feature(ifindex, 0, "ip6-not-enabled", "ip6-unicast");

	return 0;
}

int vpphook_pppoe_terminate(struct ap_session *ses, int hard)
{
	uint8_t *mac = NULL;
	uint16_t sid;
	int ret = 0;

	pppoe_get_session_mac_and_sid(ses, &mac, &sid);

	ret = vpp_iproute_flush(ses);
	if (ret)
		goto exit;
	ret = vpppolicer_remove_limiter(ses);
	if (ret)
		goto exit;
	ret = vpppoe_sync_del_pppoe_interface(mac, sid);

exit:
	return ret;
}

int vpphook_ipaddr_add(struct ap_session *ses, int ifindex, in_addr_t addr, int mask)
{
	uint32_t sw_ifindex = vpphook_get_pd(ses)->vpp_sw_if_index;
	/* setup route instead */
	return vpp_iproute_add_del(ses, 1, sw_ifindex, 0, addr, 0, 0, mask, 0);
}

int vpphook_ipaddr_add_peer(struct ap_session *ses, int ifindex, in_addr_t addr, in_addr_t peer_addr)
{
	uint32_t sw_ifindex = vpphook_get_pd(ses)->vpp_sw_if_index;
	/* setup route instead */
	return vpp_iproute_add_del(ses, 1, sw_ifindex, 0, peer_addr, 0, 0, 32, 0);
}

int vpphook_ipaddr_del(struct ap_session *ses, int ifindex, in_addr_t addr, int mask)
{
	uint32_t sw_ifindex = vpphook_get_pd(ses)->vpp_sw_if_index;
	/* remove route instead */
	return vpp_iproute_add_del(ses, 0, sw_ifindex, 0, addr, 0, 0, mask, 0);
}

int vpphook_ipaddr_del_peer(struct ap_session *ses, int ifindex, in_addr_t addr, in_addr_t peer)
{
	uint32_t sw_ifindex = vpphook_get_pd(ses)->vpp_sw_if_index;
	/* remove route instead */
	return vpp_iproute_add_del(ses, 0, sw_ifindex, 0, peer, 0, 0, 32, 0);
}

int vpphook_iproute_add(struct ap_session *ses, int ifindex, in_addr_t src, in_addr_t dst, in_addr_t gw, int proto, int mask, uint32_t prio, const char *vrf_name)
{
	uint32_t sw_ifindex = vpphook_get_pd(ses)->vpp_sw_if_index;
	return vpp_iproute_add_del(ses, 1, sw_ifindex, src, dst, gw, proto, mask, prio);
}

int vpphook_iproute_del(struct ap_session *ses, int ifindex, in_addr_t src, in_addr_t dst, in_addr_t gw, int proto, int mask, uint32_t prio, const char *vrf_name)
{
	uint32_t sw_ifindex = vpphook_get_pd(ses)->vpp_sw_if_index;
	return vpp_iproute_add_del(ses, 0, sw_ifindex, src, dst, gw, proto, mask, prio);
}

int vpphook_ip6route_add(struct ap_session *ses, int ifindex, const struct in6_addr *dst, int pref_len, const struct in6_addr *gw, int proto, uint32_t prio, const char *vrf_name)
{
	uint32_t sw_ifindex = vpphook_get_pd(ses)->vpp_sw_if_index;
	return vpp_ip6route_add_del(ses, 1, sw_ifindex, dst, pref_len, gw, proto, prio);
}

int vpphook_ip6route_del(struct ap_session *ses, int ifindex, const struct in6_addr *dst, int pref_len, const struct in6_addr *gw, int proto, uint32_t prio, const char *vrf_name)
{
	uint32_t sw_ifindex = vpphook_get_pd(ses)->vpp_sw_if_index;
	return vpp_ip6route_add_del(ses, 0, sw_ifindex, dst, pref_len, gw, proto, prio);
}

int vpphook_ip6addr_add(struct ap_session *ses, int ifindex, struct in6_addr *addr, int prefix_len)
{
	uint32_t sw_ifindex = vpphook_get_pd(ses)->vpp_sw_if_index;
	/* setup route instead */
	return vpp_ip6route_add_del(ses, 1, sw_ifindex, addr, prefix_len, NULL, 0, 0);
}

int vpphook_ip6addr_add_peer(struct ap_session *ses, int ifindex, struct in6_addr *addr, struct in6_addr *peer_addr)
{
	uint32_t sw_ifindex = vpphook_get_pd(ses)->vpp_sw_if_index;
	/* setup route instead */
	return vpp_ip6route_add_del(ses, 1, sw_ifindex, peer_addr, 128, NULL, 0, 0);
}

int vpphook_ip6addr_del(struct ap_session *ses, int ifindex, struct in6_addr *addr, int prefix_len)
{
	uint32_t sw_ifindex = vpphook_get_pd(ses)->vpp_sw_if_index;
	/* remove route instead */
	return vpp_ip6route_add_del(ses, 0, sw_ifindex, addr, prefix_len, NULL, 0, 0);
}

struct ap_session_hooks_t vpp_hooks = {
	.hooks_name = "vpp",

	.get = vpp_get,
	.put = vpp_put,

	.session_hook_init = vpphook_session_hook_init,
	.session_hook_deinit = vpphook_session_hook_deinit,

	.pppoe_create_session_interface = vpphook_pppoe_create_vpp_session_interface,
	.pppoe_terminate = vpphook_pppoe_terminate,

	.ipaddr_add = vpphook_ipaddr_add,
	.ipaddr_add_peer = vpphook_ipaddr_add_peer,
	.ipaddr_del = vpphook_ipaddr_del,
	.ipaddr_del_peer = vpphook_ipaddr_del_peer,
	.iproute_add = vpphook_iproute_add,
	.iproute_del = vpphook_iproute_del,
	.ip6route_add = vpphook_ip6route_add,
	.ip6route_del = vpphook_ip6route_del,
	.ip6addr_add = vpphook_ip6addr_add,
	.ip6addr_add_peer = vpphook_ip6addr_add_peer,
	.ip6addr_del = vpphook_ip6addr_del,

	.install_limiter = vpppolicer_install_limiter,
	.remove_limiter = vpppolicer_remove_limiter,

	.is_non_dev_ppp = 1,
	.is_non_socket_dhcpv6_nd = 1
};


static void vpphooks_init()
{
	ap_session_hooks_register(&vpp_hooks);
}

DEFINE_INIT(20, vpphooks_init);