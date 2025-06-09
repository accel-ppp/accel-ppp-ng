#ifndef VPPPOE_H
#define VPPPOE_H

void vpppoe_get();
void vpppoe_put();

struct triton_context_t;

typedef struct vpppoe_setup_pppoe_interface_ctx_t
{
    struct triton_context_t *tctx;
    void (*callback)(struct vpppoe_setup_pppoe_interface_ctx_t *ctx);
    void *priv;

    int remove_after;

    /* Output values */
    int err; /* 0 - OK */
    uint32_t ifindex;
    char ifname[16];
} vpppoe_setup_pppoe_interface_ctx_t;

int vpppoe_async_add_pppoe_interface(uint8_t *client_mac, in_addr_t *client_ip, uint16_t session_id, vpppoe_setup_pppoe_interface_ctx_t *callback_ctx);
void vpppoe_async_del_pppoe_interface(uint8_t *client_mac, in_addr_t *client_ip, uint16_t session_id, uint32_t ifindex, char *ifname);

#endif /* VPPPOE_H */