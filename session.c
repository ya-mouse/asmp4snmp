#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <net-snmp/library/asn1.h>

#include "session.h"

int snmp_build();

extern oid *netsnmp_asmpAIDPDomain;
extern oid *netsnmp_asmpASMPDomain;
extern oid *netsnmp_asmpASMPSDomain;

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

    if ((in_session->version == SNMP_VERSION_2c ||
         in_session->version == SNMP_VERSION_1)
        &&
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
                            NULL, _hook_parse,
                            NULL, _hook_build,
                            NULL, NULL,
                            NULL);
        if (session != NULL) {
            if (asmp_sess_setup(session) != 0)
                goto free;
            if (asmp_sess_login(session, "", "") != 0)
                goto free;
            fprintf(stderr, "ASMP initialized\n");
        }
    } else {
        session = NULL;
        fprintf(stderr, "SNMPv is not 3. ASMP is not initialized\n");
    }

    return session;

free:
    free(session);
    return NULL;
}

int
asmp_sess_login(netsnmp_session *session,
                const char *user, const char *passwd)
{
    oid val = 0;
    int status;
    netsnmp_pdu *pdu;
    netsnmp_pdu *response;

    pdu = snmp_pdu_create(ASMP_LOGIN_REQUEST);
    snmp_add_var(pdu, &val, 1, 's', user);
    snmp_add_var(pdu, &val, 1, 's', passwd);

    status = snmp_synch_response(session, pdu, &response);

    return status;
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
    int i;
    int rc = 0;
    size_t offset     = 0;
    size_t sz_payload = 0;
    netsnmp_variable_list *vp;
    netsnmp_transport *transport;
    struct asmp_connection *asmp;

    fprintf(stderr, "_hook_build called: %x\n", pdu->command);

    transport = snmp_sess_transport(snmp_sess_pointer(sp));
    if (transport == NULL || transport->data == NULL)
        return -1;

    asmp = transport->data;

    pkt[offset++] = ASMP_SOH;
    switch (asmp->proto) {
        case ASMP_PROTO_AIDP:
            memcpy(pkt+offset, "AIDP", 4);
            break;

        case ASMP_PROTO_ASMP:
        case ASMP_PROTO_ASMPS:
            memcpy(pkt+offset, "ASMP", 4);
            break;

        default:
            return -1;
    }
    offset += 4;
    pkt[offset++] = (pdu->msgid >> 8) & 0xff;
    pkt[offset++] =  pdu->msgid & 0xff;
    pkt[offset++] =  pdu->command;
    /* Reserve space for payload length */
    memset(pkt+offset, 0, 2);
    offset += 2;

// snmp_pdu_add_variable(pdu, name, name_len, type, value, len)

    if (SNMP_CMD_CONFIRMED(pdu->command)) {
        for (sz_payload = offset, i=0, vp = pdu->variables; vp; i++, vp = vp->next_variable) {
        }
    } else {
        for (sz_payload = offset, i=1, vp = pdu->variables; vp; i++, vp = vp->next_variable) {
            pkt[sz_payload++] = i & 0xff;
            switch (vp->type) {
                case ASN_INTEGER:
                    pkt[sz_payload++] = 0;
                    pkt[sz_payload++] = 2;
                    pkt[sz_payload++] = (*(vp->val.integer) >> 8) & 0xff;
                    pkt[sz_payload++] =  *(vp->val.integer) & 0xff;
                    break;

                case ASN_OCTET_STR:
                    pkt[sz_payload++] = (vp->val_len >> 8) & 0xff;
                    pkt[sz_payload++] =  vp->val_len & 0xff;
                    if (vp->val_len > 0)
                        memcpy(pkt+sz_payload, vp->val.string, vp->val_len);
                    sz_payload += vp->val_len;
                    break;
            }
        }
        pkt[sz_payload++] = ASMP_FIELD_TERM;
        sz_payload -= offset;
        offset -= 2;
        pkt[offset++] = (sz_payload >> 8) & 0xff;
        pkt[offset++] =  sz_payload & 0xff;
    }

    *len = offset+sz_payload;

    return rc;
}
