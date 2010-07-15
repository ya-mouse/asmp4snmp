#ifndef _ASMP__H
#define _ASMP__H

#include <inttypes.h>
#include <openssl/ssl.h>

#define ASMP_SOH                          0x01
#define ASMP_SESSION_SETUP_REQUEST        0x30
#define ASMP_SESSION_SETUP_REQUEST_FIELD_CONN_TYPE 0x01
#define ASMP_SESSION_SETUP_SSL_CONNECTION 0x01
#define ASMP_SESSION_SETUP_TCP_CONNECTION 0x02
#define ASMP_FIELD_TERM                   0xff
#define ASMP_TERMINATOR                   0x0d

struct asmp_cfg;

struct asmp_net_meth {
    int (*write)(struct asmp_cfg *cfg, const void *buf, int num);
    int (*read)(struct asmp_cfg *cfg, void *buf, int num);
};

struct asmp_cfg {
    int      tcp_sock;
    SSL     *ssl_sock;
    SSL_CTX *ssl_ctx;
    int      timeout;   /* network timeout */
    uint32_t seq;       /* sequence */
    int      is_ssl;    /* session secured */
    int      is_cert;   /* is secured session use certificate */
    struct asmp_net_meth *meth;
};

#endif
