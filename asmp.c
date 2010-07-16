#include <string.h>
#include <stdlib.h>

#include <stdio.h>
#include <unistd.h>

#include <openssl/rand.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "asmp.h"
#include "network.h"
#include "session.h"

static int _walk();

int
main(int argc, char *argv[])
{
    int    status;
    struct asmp_cfg cfg;
    //oid    name[] = { 1, 3, 6, 1, 4, 1, 10418, 7, 2 };
    oid    name[] = { 1,3,6,1,4,1,10418,7,2,1,5};

    if (argc < 2)
        return 1;
    memset(&cfg, 0, sizeof(cfg));

    RAND_status();
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_all_algorithms();
    SSLeay_add_ssl_algorithms();

//    snmp_set_do_debugging(1);
//    debug_register_tokens("asmp");

    cfg.timeout = 5000;
    cfg.is_ssl  = argc == 3 ? 1 : 0;
    cfg.host    = strdup(argv[1]);
    cfg.port    = 3211;
    status = asmp_net_connect(&cfg);
    if (status != 0) {
        fprintf(stderr, "Connection to %s:%d failed\n", cfg.host, cfg.port);
        goto close;
    }

    _walk(&cfg, name, sizeof(name)/sizeof(name[0]));

    asmp_net_logout(&cfg);

close:
    close(cfg.tcp_sock);
    return status;
}

static int
_walk(struct asmp_cfg *cfg, int *oid, int oid_len)
{
    int i;
    int rc;
    int len;
    struct asmp_pdu *pdu;
    struct asmp_pdu *response = NULL;
    uint8_t *req;

    len = 0;
    req = malloc(512);
    req[len++] = ASMP_SOH;
    req[len++] = ((3+oid_len*4+3) >> 8) & 0xff;
    req[len++] =  (3+oid_len*4+3) & 0xff;

    // AIDP VarBind
    req[len++] = 6;
    req[len++] = ((oid_len*4) >> 8) & 0xff;
    req[len++] =  (oid_len*4) & 0xff;

    for (i = 0; i<oid_len; i++) {
        req[len++] = (oid[i] >> 24) & 0xff;
        req[len++] = (oid[i] >> 16) & 0xff;
        req[len++] = (oid[i] >>  8) & 0xff;
        req[len++] =  oid[i] & 0xff;
    }
    // ASN_NULL value
    req[len++] = ASN_NULL;
    req[len++] = 0;
    req[len++] = 0;
    // AIDP VarBind end

    req[len++] = ASMP_FIELD_TERM;

    pdu = asmp_pdu_new(ASMP_SNMP_GETNEXT_REQUEST, req, len);
    if (asmp_request(cfg, pdu, &response) != 0 || response == NULL) {
        rc = -1;
        goto free;
    }

    asmp_pdu_free(response);
    rc = 0;

free:
    asmp_pdu_free(pdu);
    return rc;
}
