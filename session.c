#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <net-snmp/library/asn1.h>

#include "session.h"

int snmp_build();

oid *netsnmp_asmpAIDPDomain;
oid *netsnmp_asmpASMPDomain;
oid *netsnmp_asmpASMPSDomain;

static int _hook_parse();
static int _hook_build();

// transport = snmp_sess_transport(session)
// session->securityName contains username from '-u' arg

netsnmp_session *
asmp_open(netsnmp_session *in_session)
{
    netsnmp_session *session;
    netsnmp_transport *transport;

    if (in_session == NULL)
        return NULL;

    netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_DEFAULT_PORT,
                       ASMP_PORT);

    if (in_session->version == SNMP_VERSION_2c &&
        (!strncmp(in_session->peername, "asmp:", 5) ||
         !strncmp(in_session->peername, "asmps:", 6) ||
         !strncmp(in_session->peername, "aidp:", 5)))
    {
        /* Set TCP flag for non-AIDP connection */
        if (strncmp(in_session->peername, "aidp:", 5))
            in_session->flags |= SNMP_FLAGS_STREAM_SOCKET;

        if (in_session->flags & SNMP_FLAGS_STREAM_SOCKET) {
            transport =
                netsnmp_tdomain_transport_full("asmp", in_session->peername,
                                               in_session->local_port, "tcp",
                                               NULL);
        } else {
            transport =
                netsnmp_tdomain_transport_full("aidp", in_session->peername,
                                               in_session->local_port, "udp",
                                               NULL);
        }

// hook_create_pdu
        session = snmp_add_full(in_session,
                            transport,
                            NULL, NULL, //_hook_parse,
                            NULL, NULL, //_hook_build,
                            NULL, NULL,
                            NULL);
        if (session != NULL) {
            // TODO: ASMP_LOGIN
            fprintf(stderr, "ASMP initialized\n");
        }
    } else {
        session = NULL;
        fprintf(stderr, "SNMPv is not 3. ASMP is not initialized\n");
    }

    return session;
}

int
asmp_request(struct asmp_cfg *cfg, const struct asmp_pdu *pdu, struct asmp_pdu **response)
{
    int              rc;
    uint8_t         *buf;
    uint32_t         sz;
    struct asmp_pdu *resp;

    if (cfg->meth == NULL)
        return -1;

    cfg->seq++;
    sz  = htonl(pdu->len);
    buf = calloc(1, 13+pdu->len);
    buf[0]  = ASMP_SOH;
    memcpy(buf+1, "ASMP", 4);
    buf[5]  = (cfg->seq >> 8) & 0xff;
    buf[6]  =  cfg->seq & 0xff;
    buf[7]  = pdu->cmd;
    memcpy(buf+8, &sz, 4);
    memcpy(buf+12, pdu->data, pdu->len);
    buf[12+pdu->len] = ASMP_TERMINATOR;

//    xdump(pdu->data, pdu->len, ">> ");

    cfg->meth->write(cfg, buf, 13+pdu->len);

    cfg->meth->read(cfg, buf, 1);
    if (*buf != ASMP_SOH) {
        fprintf(stderr, "Wrong response: [%02x]\n", *buf);
        rc = -1;
        goto free;
    }
    cfg->meth->read(cfg, buf, 4);
    if (strncmp((char *)buf, "ASMP", 4)) {
        fprintf(stderr, "Wrong response: [%02x]\n", *buf);
        rc = -1;
        goto free;
    }

    resp = malloc(sizeof(struct asmp_pdu));
    cfg->meth->read(cfg, &resp->seq, 2);
    cfg->meth->read(cfg, &resp->cmd, 1);
    cfg->meth->read(cfg, &resp->len, 4);
    resp->seq = ntohs(resp->seq);
    resp->len = ntohl(resp->len);
    DEBUGMSGTL(("asmp", "[%02x][%02x][%04x]\n", resp->seq, resp->cmd, resp->len));
    if (resp->len > 0x40000) {
        fprintf(stderr, "ASMP LENGTH TOO BIG (%08x)\n", resp->len);
        rc = -2;
        goto free_resp;
    }
    resp->data = malloc(resp->len);
    cfg->meth->read(cfg, resp->data, resp->len);
    cfg->meth->read(cfg, buf, 1);
    if (*buf != ASMP_TERMINATOR) {
        fprintf(stderr, "Invalid terminator (%x)\n", *buf);
        rc = -2;
        goto free_resp;
    }

    xdump(resp->data, resp->len, "<< ");

    *response = resp;
    rc = 0;
    goto free;

free_resp:
    free(resp);

free:
    free(buf);
    return rc;
}

static int
_hook_parse(netsnmp_session * sp, netsnmp_pdu * pdu,
            u_char * pkt, size_t len)
{
    fprintf(stderr, "_hook_parse called\n");
    return -1;
}

static int
_hook_build(netsnmp_session * sp,
            netsnmp_pdu *pdu, u_char * pkt, size_t * len)
{
    int rc;
    size_t offset = 0;
    struct asmp_connection *con;
    netsnmp_transport *transport = snmp_sess_transport(sp);

    if (transport == NULL)
        return -1;

    con = transport->data;
    if (con == NULL)
        return -1;

    fprintf(stderr, "_hook_build called\n");
    rc = snmp_build(&pkt, len, &offset, sp, pdu);
    if (rc >= 0) {
        memcpy(pkt, pkt+(*len)-offset, *len);
        *len = offset;
    }
    return rc;
}
