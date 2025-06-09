#include <vapi/vapi.h>
#include <vapi/vpe.api.vapi.h>
#include <vapi/interface.api.vapi.h>
#include <vapi/pppoe.api.vapi.h>
#include <vapi/lcp.api.vapi.h>
#include <vapi/feature.api.vapi.h>

#include <linux/if_ether.h>
#include <pthread.h>

#include <memory.h>
#include <stdio.h>

#include "events.h"
#include "triton.h"

#include "vpppoe.h"

DEFINE_VAPI_MSG_IDS_VPE_API_JSON
DEFINE_VAPI_MSG_IDS_INTERFACE_API_JSON
DEFINE_VAPI_MSG_IDS_PPPOE_API_JSON
DEFINE_VAPI_MSG_IDS_LCP_API_JSON
DEFINE_VAPI_MSG_IDS_FEATURE_API_JSON

static uint32_t sc_fallback_timer = 1000;

/* rcbc - Reply CallBack Counter. Retry postponed calls if waiting less then sc_fallback_at_rcbc at curent time */
static int sc_fallback_at_rcbc = 1024;
static int sc_vpp_queue_size = 2048;

static int sc_teardown_on_max_queue = 512;

static int sc_non_lcp_mode = 0;

static struct vpp_connect_t
{
    vapi_ctx_t vapi;
    int rfcounter;

    int rcbc;

    pthread_mutex_t lock_vpp;

    struct triton_context_t tctx;
    struct triton_md_handler_t vapi_read_hnd;

	struct triton_timer_t timer;

    /* retry fallback lists */
    uint32_t retry_del_count;
    struct list_head retry_del_list;
} vpp_connect;

const char vpp_app_name[] = "accel-vpppoe";

static int vpppoe_read_events(struct triton_md_handler_t *h);
static void vpppoe_disconnect_from_vpp();
static void vpppoe_timer(struct triton_timer_t *t);

static void vpppoe_fallback_allocate_and_add_postponed_pppoe_del(uint8_t *client_mac, in_addr_t *client_ip, uint16_t session_id);

static void vpppoe_connect_to_vpp()
{
    int fd = -1;
    vapi_error_e verr = vapi_ctx_alloc(&vpp_connect.vapi);

    if (verr != VAPI_OK)
    {
        vpp_connect.vapi = NULL;
        return;
    }

    verr = vapi_connect_ex(vpp_connect.vapi, vpp_app_name, NULL, sc_vpp_queue_size, sc_vpp_queue_size, VAPI_MODE_NONBLOCKING, true, true);
    if (verr != VAPI_OK)
    {
        vapi_ctx_free(vpp_connect.vapi);
        vpp_connect.vapi = NULL;
        return;
    }

    verr = vapi_get_fd(vpp_connect.vapi, &fd);
    if (verr != VAPI_OK)
    {
        vapi_disconnect_from_vpp(vpp_connect.vapi);
        vapi_ctx_free(vpp_connect.vapi);
        vpp_connect.vapi = NULL;
        return;
    }

    memset(&vpp_connect.tctx, 0, sizeof(vpp_connect.tctx));
    memset(&vpp_connect.vapi_read_hnd, 0, sizeof(vpp_connect.vapi_read_hnd));

    vpp_connect.vapi_read_hnd.fd = fd;
    vpp_connect.vapi_read_hnd.read = vpppoe_read_events;

    // TODO: add options for triton ctx aka close and free

    vpp_connect.timer.expire = vpppoe_timer;
	vpp_connect.timer.period = sc_fallback_timer;

    // TODO: add checks
    triton_context_register(&vpp_connect.tctx, NULL);
    triton_md_register_handler(&vpp_connect.tctx, &vpp_connect.vapi_read_hnd);
    triton_md_enable_handler(&vpp_connect.vapi_read_hnd, MD_MODE_READ);
	triton_timer_add(&vpp_connect.tctx, &vpp_connect.timer, 0);
    triton_context_wakeup(&vpp_connect.tctx);
}

void vpppoe_disconnect_from_vpp()
{
    triton_timer_del(&vpp_connect.timer);
    triton_md_unregister_handler(&vpp_connect.vapi_read_hnd, 0);
    triton_context_unregister(&vpp_connect.tctx);

    vapi_disconnect(vpp_connect.vapi);
    vapi_ctx_free(vpp_connect.vapi);
    vpp_connect.vapi = NULL;
}

void vpppoe_get()
{
    int rfc = __sync_fetch_and_add(&vpp_connect.rfcounter, 1);
    if (!rfc)
        vpppoe_connect_to_vpp();
}

void vpppoe_put()
{
    int rfc = __sync_sub_and_fetch(&vpp_connect.rfcounter, 1);
    if (!rfc)
        vpppoe_disconnect_from_vpp();
}

static vapi_error_e vpppoe_set_feature_callback(struct vapi_ctx_s *ctx,
                                                void *callback_ctx,
                                                vapi_error_e rv,
                                                bool is_last,
                                                vapi_payload_feature_enable_disable_reply *reply)
{
    if (is_last)
        vpp_connect.rcbc -= 1;
    return VAPI_OK;
}

int vpppoe_set_feature(uint32_t ifindex, int is_enabled, const char *feature, const char *arc)
{
    vapi_error_e err;
    vapi_msg_feature_enable_disable *req = vapi_alloc_feature_enable_disable(vpp_connect.vapi);
    if (req == NULL)
        return -1;

    strncpy((char *)req->payload.feature_name, feature, 63);
    strncpy((char *)req->payload.arc_name, arc, 63);
    req->payload.sw_if_index = ifindex;
    req->payload.enable = is_enabled;

	pthread_mutex_lock(&vpp_connect.lock_vpp);
    vpp_connect.rcbc += 1;
    err = vapi_feature_enable_disable(vpp_connect.vapi, req, vpppoe_set_feature_callback, NULL);
	pthread_mutex_unlock(&vpp_connect.lock_vpp);

    return err;
}

typedef struct vpppoe_add_pppoe_interface_cb_ctx_t
{
    uint8_t client_mac[ETH_ALEN];
    in_addr_t client_ip;
    uint16_t session_id;
    vpppoe_setup_pppoe_interface_ctx_t *callback_ctx;
} vpppoe_add_pppoe_interface_cb_ctx_t;

int vpppoe_async_add_pppoe_interface_with_callback(vpppoe_add_pppoe_interface_cb_ctx_t *vppoe_callback_ctx);
static void vpppoe_a_add_lcp_pair_triton(vpppoe_add_pppoe_interface_cb_ctx_t *vpppoe_callback_ctx);

static void vpppoe_a_setup_features_triton(vpppoe_setup_pppoe_interface_ctx_t *vpppoe_callback_ctx) {
    vpppoe_set_feature(vpppoe_callback_ctx->ifindex, 0, "ip4-not-enabled", "ip4-unicast");
    vpppoe_set_feature(vpppoe_callback_ctx->ifindex, 0, "ip6-not-enabled", "ip6-unicast");
    triton_context_call(vpppoe_callback_ctx->tctx,  (triton_event_func)vpppoe_callback_ctx->callback, vpppoe_callback_ctx);
}

static vapi_error_e vpppoe_a_lcp_callback(struct vapi_ctx_s *ctx,
                                        void *callback_ctx,
                                        vapi_error_e rv,
                                        bool is_last,
                                        vapi_payload_lcp_itf_pair_add_del_reply *reply)
{

    if (is_last)
        vpp_connect.rcbc -= 1;

    vpppoe_add_pppoe_interface_cb_ctx_t *vpppoe_callback_ctx = (vpppoe_add_pppoe_interface_cb_ctx_t *)callback_ctx;

    if (callback_ctx != NULL && reply != NULL && rv == VAPI_OK)
    {
        triton_context_call(&vpp_connect.tctx,  (triton_event_func)vpppoe_a_setup_features_triton, vpppoe_callback_ctx->callback_ctx);
        free(vpppoe_callback_ctx);
    } else {
        fprintf(stderr, "\e[1;31m --| %s unexpected issue ctx %p reply %p rv %d rcbc %d\e[0m\n", __FUNCTION__, callback_ctx, reply, rv, vpp_connect.rcbc);
        if (vpppoe_callback_ctx != NULL) {
                        
            fprintf(stderr, "\e[1;31m --| %s ISSUE during lcp creation sid %d rcbc %d\e[0m\n", __FUNCTION__, vpppoe_callback_ctx->session_id, vpp_connect.rcbc);
 
            vpppoe_fallback_allocate_and_add_postponed_pppoe_del(vpppoe_callback_ctx->client_mac, &vpppoe_callback_ctx->client_ip, vpppoe_callback_ctx->session_id);

            vpppoe_callback_ctx->callback_ctx->err = rv;
            triton_context_call(vpppoe_callback_ctx->callback_ctx->tctx,  (triton_event_func)vpppoe_callback_ctx->callback_ctx->callback, vpppoe_callback_ctx->callback_ctx);
            free(vpppoe_callback_ctx);
        }
    }
    return rv;
}

void vpppoe_a_add_lcp_pair_triton(vpppoe_add_pppoe_interface_cb_ctx_t *vpppoe_callback_ctx) {
    vapi_error_e err;
    vapi_msg_lcp_itf_pair_add_del *req = vapi_alloc_lcp_itf_pair_add_del(vpp_connect.vapi);

    // TODO check logic
    if (req == NULL)
    {
        fprintf(stderr, "\e[1;31m --| %s can't allocate lcp add request ifindex %d rcbc %d\e[0m\n", __FUNCTION__, vpppoe_callback_ctx->callback_ctx->ifindex, vpp_connect.rcbc);
        return;
    }

    snprintf((char *)req->payload.host_if_name, 15, "vppp%d", vpppoe_callback_ctx->callback_ctx->ifindex);
    strncpy(vpppoe_callback_ctx->callback_ctx->ifname, (char *)req->payload.host_if_name, 15);
    // strncpy((char *)req->payload.host_if_name, host_if_name, 15);
    req->payload.sw_if_index = vpppoe_callback_ctx->callback_ctx->ifindex;
    req->payload.host_if_type = LCP_API_ITF_HOST_TUN;
    req->payload.is_add = 1;

	pthread_mutex_lock(&vpp_connect.lock_vpp);
    vpp_connect.rcbc += 1;
    err = vapi_lcp_itf_pair_add_del(vpp_connect.vapi, req, vpppoe_a_lcp_callback, vpppoe_callback_ctx);
	pthread_mutex_unlock(&vpp_connect.lock_vpp);

    if (err != VAPI_OK)
    {
        if (vpppoe_callback_ctx != NULL)
        {
            fprintf(stderr, "\e[1;31m --| %s can't send lcp pair creation request sid %d rcbc %d\e[0m\n", __FUNCTION__, vpppoe_callback_ctx->session_id, vpp_connect.rcbc);
  
            vpppoe_fallback_allocate_and_add_postponed_pppoe_del(vpppoe_callback_ctx->client_mac, &vpppoe_callback_ctx->client_ip, vpppoe_callback_ctx->session_id);

            vpppoe_callback_ctx->callback_ctx->err = err;
            triton_context_call(vpppoe_callback_ctx->callback_ctx->tctx,  (triton_event_func)vpppoe_callback_ctx->callback_ctx->callback, vpppoe_callback_ctx->callback_ctx);
            free(vpppoe_callback_ctx);
        }
    }
}

static vapi_error_e vpppoe_a_session_add_reply_callback(struct vapi_ctx_s *ctx,
                                                      void *callback_ctx,
                                                      vapi_error_e rv,
                                                      bool is_last,
                                                      vapi_payload_pppoe_add_del_session_reply *reply)
{

    if (is_last)
        vpp_connect.rcbc -= 1;

    vpppoe_add_pppoe_interface_cb_ctx_t *vpppoe_callback_ctx = (vpppoe_add_pppoe_interface_cb_ctx_t *)callback_ctx;
    if (callback_ctx != NULL && reply != NULL && rv == VAPI_OK)
    {
        vpppoe_callback_ctx->callback_ctx->ifindex = reply->sw_if_index;
        if (sc_non_lcp_mode) {
            triton_context_call(&vpp_connect.tctx,  (triton_event_func)vpppoe_a_setup_features_triton, vpppoe_callback_ctx->callback_ctx);
            free(vpppoe_callback_ctx);
        } else {
            triton_context_call(&vpp_connect.tctx,  (triton_event_func)vpppoe_a_add_lcp_pair_triton, vpppoe_callback_ctx);
        }
        fprintf(stderr, "\e[1;32m --| %s add pppoe session ifindex %d rcbc %d \e[0m\n", __FUNCTION__, vpppoe_callback_ctx->callback_ctx->ifindex, vpp_connect.rcbc);
    } else {
        fprintf(stderr, "\e[1;31m --| %s unexpected issue ctx %p reply %p rv %d rcbc %d\e[0m\n", __FUNCTION__, callback_ctx, reply, rv, vpp_connect.rcbc);

        if (vpppoe_callback_ctx != NULL) {

            vpppoe_callback_ctx->callback_ctx->err = rv;
            triton_context_call(vpppoe_callback_ctx->callback_ctx->tctx,  (triton_event_func)vpppoe_callback_ctx->callback_ctx->callback, vpppoe_callback_ctx->callback_ctx);
            free(vpppoe_callback_ctx);
        }
    }

    return rv;
}

int vpppoe_async_add_pppoe_interface_with_callback(vpppoe_add_pppoe_interface_cb_ctx_t *vppoe_callback_ctx) {
    vapi_error_e err;

    vapi_msg_pppoe_add_del_session *req = vapi_alloc_pppoe_add_del_session(vpp_connect.vapi);
    if (req == NULL) {
        fprintf(stderr, "\e[1;31m --| %s can't allocate pppoe add request session %d rcbc %d\e[0m\n", __FUNCTION__, vppoe_callback_ctx->session_id, vpp_connect.rcbc);
         
        return -1;
    }

    vppoe_callback_ctx->callback_ctx->err = 0;
    vppoe_callback_ctx->callback_ctx->ifindex = 0;

    req->payload.client_ip.af = ADDRESS_IP4;
    memcpy(req->payload.client_ip.un.ip4, &vppoe_callback_ctx->client_ip, sizeof(vppoe_callback_ctx->client_ip));
    memcpy(req->payload.client_mac, vppoe_callback_ctx->client_mac, ETH_ALEN);

    req->payload.is_add = 1;
    req->payload.session_id = vppoe_callback_ctx->session_id;
    req->payload.disable_fib = 1;

	pthread_mutex_lock(&vpp_connect.lock_vpp);
    vpp_connect.rcbc += 1;
    err = vapi_pppoe_add_del_session(vpp_connect.vapi, req, vpppoe_a_session_add_reply_callback, vppoe_callback_ctx);
	pthread_mutex_unlock(&vpp_connect.lock_vpp);

    if (err != VAPI_OK) {
        if (vppoe_callback_ctx != NULL) {
            fprintf(stderr, "\e[1;31m --| %s can't send pppoe creation request sid %d rcbc %d\e[0m\n", __FUNCTION__, vppoe_callback_ctx->session_id, vpp_connect.rcbc);
            vppoe_callback_ctx->callback_ctx->err = err;
            triton_context_call(vppoe_callback_ctx->callback_ctx->tctx,  (triton_event_func)vppoe_callback_ctx->callback_ctx->callback, vppoe_callback_ctx->callback_ctx);
            free(vppoe_callback_ctx);
        }
    }

    return err;
}

int vpppoe_async_add_pppoe_interface(uint8_t *client_mac, in_addr_t *client_ip, uint16_t session_id, vpppoe_setup_pppoe_interface_ctx_t *callback_ctx)
{
    if (vpp_connect.rcbc >= sc_teardown_on_max_queue) {
        fprintf(stderr, "\e[1;31m --| %s TOO much request sid %d rcbc %d\e[0m\n", __FUNCTION__, session_id, vpp_connect.rcbc);
        callback_ctx->err = -100;
        triton_context_call(callback_ctx->tctx,  (triton_event_func)callback_ctx->callback, callback_ctx);
        return -100;
    }

    vpppoe_add_pppoe_interface_cb_ctx_t *vpppoe_callback_ctx = malloc(sizeof(*vpppoe_callback_ctx));
    memset(vpppoe_callback_ctx, 0, sizeof(*vpppoe_callback_ctx));
    
    memcpy(&vpppoe_callback_ctx->client_ip, client_ip, sizeof(*client_ip));
    memcpy(vpppoe_callback_ctx->client_mac, client_mac, ETH_ALEN);
    vpppoe_callback_ctx->session_id = session_id;
    vpppoe_callback_ctx->callback_ctx = callback_ctx;

    return vpppoe_async_add_pppoe_interface_with_callback(vpppoe_callback_ctx);
}

typedef struct vpppoe_del_pppoe_interface_cb_ctx_t
{
    uint8_t mac[ETH_ALEN];
    in_addr_t client_ip;
    uint16_t session_id;
    uint32_t ifindex;
    char ifname[16];

    /* retry fallback */
    uint32_t retrys;
	struct list_head entry;
    uint32_t retry_at; /* 0 - from lcp delete routine, 1 - from pppoe session delete routine */
} vpppoe_del_pppoe_interface_cb_ctx_t;


static void vpppoe_async_del_pppoe_interface_with_callback(vpppoe_del_pppoe_interface_cb_ctx_t *callback_ctx);
static void vpppoe_a_del_session_triton(vpppoe_del_pppoe_interface_cb_ctx_t *vpppoe_callback_ctx);

static void vpppoe_retry_del_later(vpppoe_del_pppoe_interface_cb_ctx_t *ctx) {
    ctx->retrys += 1;
    vpp_connect.retry_del_count += 1;
	list_add_tail(&ctx->entry, &vpp_connect.retry_del_list);
}

void vpppoe_fallback_allocate_and_add_postponed_pppoe_del(uint8_t *client_mac, in_addr_t *client_ip, uint16_t session_id) {

    vpppoe_del_pppoe_interface_cb_ctx_t *callback_ctx = malloc(sizeof(*callback_ctx));
    memset(callback_ctx, 0, sizeof(*callback_ctx));
    memcpy(&callback_ctx->mac, client_mac, ETH_ALEN);
    memcpy(&callback_ctx->client_ip, client_ip, sizeof(*client_ip));
    callback_ctx->session_id = session_id;
    
    callback_ctx->retry_at = 1;
    vpppoe_retry_del_later(callback_ctx);
}

static void vpppoe_launch_del_retrys(uint32_t count) {
    if (vpp_connect.retry_del_count) {

        uint32_t i = 0;
	    struct list_head *pos, *n;
        vpppoe_del_pppoe_interface_cb_ctx_t *callback_ctx;

        list_for_each_safe(pos, n, &vpp_connect.retry_del_list) {
            callback_ctx = list_entry(pos, typeof(*callback_ctx), entry);

            vpp_connect.retry_del_count -= 1;
			list_del(&callback_ctx->entry);
        
            fprintf(stderr, "\033[104m --| %s RETRY DEL  %d ifname %16s rcbc %d retry %d\e[0m\n", __FUNCTION__, callback_ctx->ifindex, callback_ctx->ifname, vpp_connect.rcbc, vpp_connect.retry_del_count);
 
            if (callback_ctx->retry_at == 0)
                vpppoe_async_del_pppoe_interface_with_callback(callback_ctx);
            else
                vpppoe_a_del_session_triton(callback_ctx);

            ++i;
            if (i > count) {
                break;
            }
        }
    }
}

static vapi_error_e vpppoe_a_del_session_add_reply_callback(struct vapi_ctx_s *ctx,
                                                      void *callback_ctx,
                                                      vapi_error_e rv,
                                                      bool is_last,
                                                      vapi_payload_pppoe_add_del_session_reply *reply)
{
    if (is_last)
        vpp_connect.rcbc -= 1;

    vpppoe_del_pppoe_interface_cb_ctx_t *vpppoe_callback_ctx = (vpppoe_del_pppoe_interface_cb_ctx_t *)callback_ctx;
    if (callback_ctx && rv == VAPI_OK) {
        fprintf(stderr, "\e[1;33m --| %s del pppoe %p %p %d ifindex %d ifname %s rcbc %d \e[0m\n", __FUNCTION__, callback_ctx, reply, rv, vpppoe_callback_ctx->ifindex, vpppoe_callback_ctx->ifname, vpp_connect.rcbc);
        free(vpppoe_callback_ctx);

    } else {
        fprintf(stderr, "\e[1;31m --| %s some issue in pppoe del - adding to the retry list - responce %d ifindex %d ifname %16s rcbc %d retrys %d\e[0m\n", __FUNCTION__, rv, vpppoe_callback_ctx->ifindex, vpppoe_callback_ctx->ifname, vpp_connect.rcbc, vpp_connect.retry_del_count);
        vpppoe_callback_ctx->retry_at = 1;
        vpppoe_retry_del_later(vpppoe_callback_ctx);
  
    }

    return VAPI_OK;
}

void vpppoe_a_del_session_triton(vpppoe_del_pppoe_interface_cb_ctx_t *vpppoe_callback_ctx) {

    vapi_error_e err;

    if (vpp_connect.rcbc >= sc_teardown_on_max_queue) {
        fprintf(stderr, "\e[1;31m --| %s TOO  much DEL LCP request - add to postpone list sid %d ifindex %d rcbc %d\e[0m\n", __FUNCTION__, vpppoe_callback_ctx->session_id, vpppoe_callback_ctx->ifindex, vpp_connect.rcbc);
        vpppoe_callback_ctx->retry_at = 1;
        vpppoe_retry_del_later(vpppoe_callback_ctx);
        return;
    }

    vapi_msg_pppoe_add_del_session *req = vapi_alloc_pppoe_add_del_session(vpp_connect.vapi);
    if (req == NULL) {
        fprintf(stderr, "\e[1;31m --| %s can't allocate pppoe delete request ifindex %d ifname %16s rcbc %d\e[0m\n", __FUNCTION__, vpppoe_callback_ctx->ifindex, vpppoe_callback_ctx->ifname, vpp_connect.rcbc);
        return;
    }

    req->payload.client_ip.af = ADDRESS_IP4;
    memcpy(req->payload.client_ip.un.ip4, &vpppoe_callback_ctx->client_ip, sizeof(vpppoe_callback_ctx->client_ip));
    memcpy(req->payload.client_mac, &vpppoe_callback_ctx->mac, ETH_ALEN);

    req->payload.is_add = 0;
    req->payload.session_id = vpppoe_callback_ctx->session_id;
    // req->payload.disable_fib = 1;


	pthread_mutex_lock(&vpp_connect.lock_vpp);
    vpp_connect.rcbc += 1;
    err = vapi_pppoe_add_del_session(vpp_connect.vapi, req, vpppoe_a_del_session_add_reply_callback, vpppoe_callback_ctx);
	pthread_mutex_unlock(&vpp_connect.lock_vpp);

    if (err != VAPI_OK) {
        fprintf(stderr, "\e[1;31m --| %s cant SEND pppoe del - adding to the retry list - responce %d ifindex %d ifname %16s rcbc %d retrys %d\e[0m\n", __FUNCTION__, err, vpppoe_callback_ctx->ifindex, vpppoe_callback_ctx->ifname, vpp_connect.rcbc, vpp_connect.retry_del_count);
        vpppoe_callback_ctx->retry_at = 1;
        vpppoe_retry_del_later(vpppoe_callback_ctx);
    }
}

static vapi_error_e vpppoe_a_del_lcp_callback(struct vapi_ctx_s *ctx,
                                        void *callback_ctx,
                                        vapi_error_e rv,
                                        bool is_last,
                                        vapi_payload_lcp_itf_pair_add_del_reply *reply)
{

    if (is_last)
        vpp_connect.rcbc -= 1;

    vpppoe_del_pppoe_interface_cb_ctx_t *vpppoe_callback_ctx = (vpppoe_del_pppoe_interface_cb_ctx_t *)callback_ctx;

    if (callback_ctx != NULL && rv == VAPI_OK)
    {
        triton_context_call(&vpp_connect.tctx,  (triton_event_func)vpppoe_a_del_session_triton, vpppoe_callback_ctx);

    } else {
        fprintf(stderr, "\e[1;31m --| %s unexpected issue ctx %p reply %p rv %d rcbc %d\e[0m\n", __FUNCTION__, callback_ctx, reply, rv, vpp_connect.rcbc);
        if (vpppoe_callback_ctx != NULL) {
            fprintf(stderr, "\e[1;31m --| %s some issue in lcp del - adding to the retry list - responce %d ifindex %d ifname %16s rcbc %d retrys %d\e[0m\n", __FUNCTION__, rv, vpppoe_callback_ctx->ifindex, vpppoe_callback_ctx->ifname, vpp_connect.rcbc, vpp_connect.retry_del_count);
            vpppoe_callback_ctx->retry_at = 0;
            vpppoe_retry_del_later(vpppoe_callback_ctx);
  
        }
    }

    return VAPI_OK;
}

void vpppoe_async_del_pppoe_interface_with_callback(vpppoe_del_pppoe_interface_cb_ctx_t *callback_ctx) {

    vapi_error_e err;

    if (vpp_connect.rcbc >= sc_teardown_on_max_queue) {
        fprintf(stderr, "\e[1;31m --| %s TOO  much DEL request - add to postpone list sid %d ifindex %d rcbc %d\e[0m\n", __FUNCTION__, callback_ctx->session_id, callback_ctx->ifindex, vpp_connect.rcbc);
        callback_ctx->retry_at = 0;
        vpppoe_retry_del_later(callback_ctx);
        return;
    }

    vapi_msg_lcp_itf_pair_add_del *req = vapi_alloc_lcp_itf_pair_add_del(vpp_connect.vapi);

    if (req == NULL)
    {
        fprintf(stderr, "\e[1;31m --| %s can't allocate lcp delete request ifindex %d ifname %16s rcbc %d\e[0m\n", __FUNCTION__,
             callback_ctx->ifindex, callback_ctx->ifname, vpp_connect.rcbc);
        return;
    }

    strncpy((char *)req->payload.host_if_name, callback_ctx->ifname, 15);
    req->payload.sw_if_index = callback_ctx->ifindex;
    req->payload.host_if_type = LCP_API_ITF_HOST_TUN;
    req->payload.is_add = 0;


	pthread_mutex_lock(&vpp_connect.lock_vpp);
    vpp_connect.rcbc += 1;
    err = vapi_lcp_itf_pair_add_del(vpp_connect.vapi, req, vpppoe_a_del_lcp_callback, callback_ctx);
	pthread_mutex_unlock(&vpp_connect.lock_vpp);
    
    if (err != VAPI_OK) {
        fprintf(stderr, "\e[1;31m --| %s cant SEND lcp del - adding to the retry list - responce %d ifindex %d ifname %16s rcbc %d retrys %d\e[0m\n", __FUNCTION__, err, callback_ctx->ifindex, callback_ctx->ifname, vpp_connect.rcbc, vpp_connect.retry_del_count);
        callback_ctx->retry_at = 0;
        vpppoe_retry_del_later(callback_ctx);
    }
}

void vpppoe_async_del_pppoe_interface(uint8_t *client_mac, in_addr_t *client_ip, uint16_t session_id, uint32_t ifindex, char *ifname) {
    vpppoe_del_pppoe_interface_cb_ctx_t *callback_ctx = malloc(sizeof(*callback_ctx));
    memset(callback_ctx, 0, sizeof(*callback_ctx));
    memcpy(&callback_ctx->mac, client_mac, ETH_ALEN);
    memcpy(&callback_ctx->client_ip, client_ip, sizeof(*client_ip));
    callback_ctx->session_id = session_id;

    callback_ctx->ifindex = ifindex;
    strncpy((char *)&callback_ctx->ifname, ifname, 15);

    if (sc_non_lcp_mode) {
        vpppoe_a_del_session_triton(callback_ctx);
    } else {
        vpppoe_async_del_pppoe_interface_with_callback(callback_ctx);
    }
}


/* NOTE DIRTY HACKS ALL AROUND! */
int vpppoe_read_events(struct triton_md_handler_t *h)
{
	pthread_mutex_lock(&vpp_connect.lock_vpp);
    vapi_dispatch(vpp_connect.vapi);
	pthread_mutex_unlock(&vpp_connect.lock_vpp);

    return 0;
}

void vpppoe_timer(struct triton_timer_t *t) {

    if (vpp_connect.rcbc < sc_fallback_at_rcbc) {
        vpppoe_launch_del_retrys(sc_teardown_on_max_queue);
    }
    /* HACK */
    vpppoe_read_events(NULL);
}

static void vpppoe_load_config(void)
{
	char *opt;

	opt = conf_get_opt("vpp", "queue_size");
	if (opt)
		sc_vpp_queue_size = atoi(opt);

	opt = conf_get_opt("vpp", "fallback_timer");
	if (opt)
		sc_fallback_timer = atoi(opt);

	opt = conf_get_opt("vpp", "teardown_at_max_requests");
	if (opt)
		sc_fallback_at_rcbc = atoi(opt);

    opt = conf_get_opt("vpp", "fallback_requests");
	if (opt)
		sc_teardown_on_max_queue = atoi(opt);
        
    opt = conf_get_opt("vpp", "non_lcp_mode");
	if (opt)
		sc_non_lcp_mode = atoi(opt);        
}

static void vpppoe_init()
{
    memset(&vpp_connect, 0, sizeof(vpp_connect));
    INIT_LIST_HEAD(&vpp_connect.retry_del_list);
    pthread_mutex_init(&vpp_connect.lock_vpp, NULL);
    
	vpppoe_load_config();

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)vpppoe_load_config);
}

DEFINE_INIT(20, vpppoe_init);