/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
 */

#include "ap_session.h"
#include "iputils.h"
#include "vppiputils.h"

#include "accel_iputils.h"

/* TODO: refactore & redesign */

__export int accel_ipaddr_add(struct ap_session *ses, int ifindex, in_addr_t addr, int mask)
{
#ifdef HAVE_VPP
	if (ses->non_dev_ppp_fixup != NULL)
	{
		/* setup route instead */
		return vpp_iproute_add_del(ses, 1, ses->vpp_sw_if_index, 0, addr, 0, 0, mask, 0);
	}
	else
#endif
	{
		return ipaddr_add(ifindex, addr, mask);
	}
}

__export int accel_ipaddr_add_peer(struct ap_session *ses, int ifindex, in_addr_t addr, in_addr_t peer_addr)
{
#ifdef HAVE_VPP
	if (ses->non_dev_ppp_fixup != NULL)
	{
		/* setup route instead */
		return vpp_iproute_add_del(ses, 1, ses->vpp_sw_if_index, 0, peer_addr, 0, 0, 32, 0);
	}
	else
#endif
	{
		return ipaddr_add_peer(ifindex, addr, peer_addr);
	}
}

__export int accel_ipaddr_del(struct ap_session *ses, int ifindex, in_addr_t addr, int mask)
{
#ifdef HAVE_VPP
	if (ses->non_dev_ppp_fixup != NULL)
	{
		/* remove route instead */
		return vpp_iproute_add_del(ses, 0, ses->vpp_sw_if_index, 0, addr, 0, 0, mask, 0);
	}
	else
#endif
	{
		return ipaddr_del(ifindex, addr, mask);
	}
}

__export int accel_ipaddr_del_peer(struct ap_session *ses, int ifindex, in_addr_t addr, in_addr_t peer)
{
#ifdef HAVE_VPP
	if (ses->non_dev_ppp_fixup != NULL)
	{
		/* remove route instead */
		return vpp_iproute_add_del(ses, 0, ses->vpp_sw_if_index, 0, peer, 0, 0, 32, 0);
	}
	else
#endif
	{
		return ipaddr_del_peer(ifindex, addr, peer);
	}
}

__export int accel_iproute_add(struct ap_session *ses, int ifindex, in_addr_t src, in_addr_t dst, in_addr_t gw, int proto, int mask, uint32_t prio, const char *vrf_name)
{
#ifdef HAVE_VPP
	if (ses->non_dev_ppp_fixup != NULL)
	{
		return vpp_iproute_add_del(ses, 1, ses->vpp_sw_if_index, src, dst, gw, proto, mask, prio);
	}
	else
#endif
	{
		return iproute_add(ifindex, src, dst, gw, proto, mask, prio, vrf_name);
	}
}

__export int accel_iproute_del(struct ap_session *ses, int ifindex, in_addr_t src, in_addr_t dst, in_addr_t gw, int proto, int mask, uint32_t prio, const char *vrf_name)
{
#ifdef HAVE_VPP
	if (ses->non_dev_ppp_fixup != NULL)
	{
		return vpp_iproute_add_del(ses, 0, ses->vpp_sw_if_index, src, dst, gw, proto, mask, prio);
	}
	else
#endif
	{
		return iproute_del(ifindex, src, dst, gw, proto, mask, prio, vrf_name);
	}
}

__export int accel_ip6route_add(struct ap_session *ses, int ifindex, const struct in6_addr *dst, int pref_len, const struct in6_addr *gw, int proto, uint32_t prio, const char *vrf_name)
{
#ifdef HAVE_VPP
	if (ses->non_dev_ppp_fixup != NULL)
	{
		return vpp_ip6route_add_del(ses, 1, ses->vpp_sw_if_index, dst, pref_len, gw, proto, prio);
	}
	else
#endif
	{
		return ip6route_add(ifindex, dst, pref_len, gw, proto, prio, vrf_name);
	}
}

__export int accel_ip6route_del(struct ap_session *ses, int ifindex, const struct in6_addr *dst, int pref_len, const struct in6_addr *gw, int proto, uint32_t prio, const char *vrf_name)
{
#ifdef HAVE_VPP
	if (ses->non_dev_ppp_fixup != NULL)
	{
		return vpp_ip6route_add_del(ses, 0, ses->vpp_sw_if_index, dst, pref_len, gw, proto, prio);
	}
	else
#endif
	{
		return ip6route_del(ifindex, dst, pref_len, gw, proto, prio, vrf_name);
	}
}

__export int accel_ip6addr_add(struct ap_session *ses, int ifindex, struct in6_addr *addr, int prefix_len)
{
#ifdef HAVE_VPP
	if (ses->non_dev_ppp_fixup != NULL)
	{
		/* setup route instead */
		return vpp_ip6route_add_del(ses, 1, ses->vpp_sw_if_index, addr, prefix_len, NULL, 0, 0);
	}
	else
#endif
	{
		return ip6addr_add(ifindex, addr, prefix_len);
	}
}

__export int accel_ip6addr_add_peer(struct ap_session *ses, int ifindex, struct in6_addr *addr, struct in6_addr *peer_addr)
{
#ifdef HAVE_VPP
	if (ses->non_dev_ppp_fixup != NULL)
	{
		/* setup route instead */
		return vpp_ip6route_add_del(ses, 1, ses->vpp_sw_if_index, peer_addr, 128, NULL, 0, 0);
	}
	else
#endif
	{
		return ip6addr_add_peer(ifindex, addr, peer_addr);
	}
}

__export int accel_ip6addr_del(struct ap_session *ses, int ifindex, struct in6_addr *addr, int prefix_len)
{
#ifdef HAVE_VPP
	if (ses->non_dev_ppp_fixup != NULL)
	{
		/* remove route instead */
		return vpp_ip6route_add_del(ses, 0, ses->vpp_sw_if_index, addr, prefix_len, NULL, 0, 0);
	}
	else
#endif
	{
		return ip6addr_del(ifindex, addr, prefix_len);
	}
}