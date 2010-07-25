#ifndef _ASMP__H
#define _ASMP__H

#include <openssl/ssl.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#define ASMP_PORT                         3211

#define ASMP_SOH                          0x01
#define ASMP_LOGIN_REQUEST                0x01
#define ASMP_LOGOUT_REQUEST               0x02
#define ASMP_SNMP_GET_REQUEST             0x10
#define ASMP_SNMP_GETNEXT_REQUEST         0x11
#define ASMP_SESSION_SETUP_REQUEST        0x30
#define ASMP_VERSION_REQUEST              0x31
#define ASMP_SESSION_SETUP_REQUEST_FIELD_CONN_TYPE 0x01
#define ASMP_SESSION_SETUP_SSL_CONNECTION 0x01
#define ASMP_SESSION_SETUP_TCP_CONNECTION 0x02
#define ASMP_FIELD_TERM                   0xff
#define ASMP_TERMINATOR                   0x0d

#define AIDP_DISCOVER_REQUEST             0x01
#define AIDP_DISCOVER_REPLY               0x81

#define TRANSPORT_DOMAIN_AIDP             1,3,6,1,2,1,100,1,10418,1
#define TRANSPORT_DOMAIN_ASMP             1,3,6,1,2,1,100,1,10418,2
#define TRANSPORT_DOMAIN_ASMPS            1,3,6,1,2,1,100,1,10418,3

enum {
    ASMP_PROTO_AIDP,
    ASMP_PROTO_ASMP,
    ASMP_PROTO_ASMPS
};

struct asmp_cfg;
struct asmp_connection;

struct asmp_net_meth {
    int (*write)(struct asmp_cfg *cfg, const void *buf, int num);
    int (*read)(struct asmp_cfg *cfg, void *buf, int num);
};

struct asmpnet_meth {
    int (*send)(struct asmp_connection *con, const void *buf, int num);
    int (*recv)(struct asmp_connection *con, void *buf, int num);
};

struct asmp_cfg {
    int      tcp_sock;
    SSL     *ssl_sock;
    SSL_CTX *ssl_ctx;
    struct asmp_net_meth *meth;

    char    *host;      /* hostname */
    uint16_t port;      /* port */
    int      timeout;   /* network timeout */

    uint32_t seq;       /* sequence */
    int      is_ssl;    /* session secured */
    int      is_cert;   /* is secured session use certificate */
};

struct asmp_pdu {
    uint16_t seq;
    uint8_t  cmd;
    uint32_t len;
    uint8_t *data;
};

struct asmp_connection {
    int      sock;
    SSL     *ssl_sock;
    SSL_CTX *ssl_ctx;
    struct asmpnet_meth *tcp_meth;
    void    *addr_pair;
    int      proto;
    uint32_t seq;
};

void netsnmp_aidp_ctor();
void netsnmp_asmp_ctor();

#endif
