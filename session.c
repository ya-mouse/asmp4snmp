#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <net-snmp/library/asn1.h>

#include "session.h"
#include "aidp.h"

int snmp_build();

extern oid *netsnmp_asmpAIDPDomain;
extern oid *netsnmp_asmpASMPDomain;
extern oid *netsnmp_asmpASMPSDomain;

static int _hook_check();
static int _hook_parse();
static int _hook_build();
static int _asmp_synch_input();

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
                            NULL, _hook_check,
                            NULL);
        if (session != NULL &&
            (session->flags & SNMP_FLAGS_STREAM_SOCKET)) {
            if (asmp_sess_setup(session) != 0)
                goto free;
            if (asmp_sess_login(session,
                    ((struct asmp_connection *)transport->data)->proto ==
                        ASMP_PROTO_ASMPS ? session->securityName : "",
                    "") != 0) {
                goto free;
            }
            fprintf(stderr, "ASMP initialized\n");
        }
    } else {
        session = NULL;
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
    netsnmp_transport *transport;
    struct asmp_connection *asmp;

    transport = snmp_sess_transport(snmp_sess_pointer(session));
    if (transport == NULL || transport->data == NULL)
        return -1;

    asmp = transport->data;

    pdu = snmp_pdu_create(ASMP_LOGIN_REQUEST);
    snmp_add_var(pdu, &val, 1, 's', user   == NULL ? "" : user);
    snmp_add_var(pdu, &val, 1, 's', passwd == NULL ? "" : passwd);
    asmp->user = user == NULL ? "" : strdup(user);

    status = asmp_synch_response(session, pdu, &response);

    return status;
}

int
asmp_sess_logout(netsnmp_session *session)
{
    netsnmp_pdu *pdu;
    netsnmp_pdu *response;

    pdu = snmp_pdu_create(ASMP_LOGOUT_REQUEST);

    return asmp_synch_response(session, pdu, &response);
}

int
asmp_synch_response(netsnmp_session * ss,
                    netsnmp_pdu *pdu, netsnmp_pdu **response)
{
    return snmp_synch_response_cb(ss, pdu, response, _asmp_synch_input);
}

static int
_hook_check(u_char * pkt, size_t len)
{
    size_t payload_len;

    if (pkt[0] != 1) {
        fprintf(stderr, "asmp_pdu_check: wrong packet (No SOH)\n");
        return -1;
    }

    if (strncmp((char *)pkt+1, "AIDP", 4) &&
        strncmp((char *)pkt+1, "ASMP", 4)) {
        fprintf(stderr, "asmp_pdu_check: wrong packet (Bad Signature)\n");
        return -1;
    }

    if (len < 8) {
        fprintf(stderr, "asmp_pdu_check: wrong packet (Too short)\n");
        return -1;
    }

    payload_len = ntohl(*((uint32_t *)(pkt+8)));

    if (payload_len > len-13) {
        fprintf(stderr,
                "asmp_pdu_check: wrong packet (Payload length bigger than packet length: %d <> %d)\n",
                payload_len, len-13);
        return -1;
    }

    return len;
}

static int
_hook_parse(netsnmp_session * sp, netsnmp_pdu * pdu,
            u_char * pkt, size_t len)
{
    int      i;
    int      rc;
    u_char  *p;
    oid      val;
    int      payload_len;
    netsnmp_transport *transport;
    struct asmp_connection *asmp;

    transport = snmp_sess_transport(snmp_sess_pointer(sp));
    if (transport == NULL || transport->data == NULL)
        return -1;

    asmp = transport->data;

    pdu->msgid   = pdu->reqid = (pkt[5] << 8) | pkt[6];
    pdu->command = pkt[7];

    if (pdu->command == 0x90 || pdu->command == 0x91)
        rc = 1;
    else
        rc = SNMP_ERR_NOERROR;

    p = pkt+12;
    payload_len = ntohl(*((uint32_t *)(pkt+8)));
    while (payload_len > 1) {
        uint16_t vlen;

        if (*p == ASMP_FIELD_TERM)
            break;

        val  = *p;
        vlen = ntohs(*((uint16_t *)(p+1)));

        if (asmp->proto != ASMP_PROTO_AIDP) {
            switch (val) {
            case 1:
                if (pdu->command >= 0x90 && pdu->command <= 0x92)
                    pdu->errstat = ntohs(*((uint16_t *)(p+3)));
                break;

            case 2:
                if (pdu->command >= 0x90 && pdu->command <= 0x92)
                    pdu->errindex = ntohs(*((uint16_t *)(p+3)));
                break;

            case 3:
                if (pdu->command >= 0x90 && pdu->command <= 0x92) {
                    int     nlen;
                    oid    *name = NULL;
                    netsnmp_variable_list *var = NULL;

                    p += 3;
                    if (*p != ASN_OBJECT_ID) {
                        fprintf(stderr, "Wrong VarBind data\n");
                        return rc;
                    }
                    while (vlen > 0) {
                        nlen = (*(p+1) << 8 | *(p+2));

                        switch (*p) {
                        case ASN_OBJECT_ID:
                            name = calloc(1, nlen);
                            //fprintf(stderr, "OID: ");
                            for (p += 3, i=0; i<nlen/sizeof(oid); i++, p += 4) {
                                name[i] = *p     << 24 |
                                          *(p+1) << 16 |
                                          *(p+2) << 8  |
                                          *(p+3);
                                //fprintf(stderr, ".%d", name[i]);
                            }
                            //fprintf(stderr, "\n");
                            /* move pointer back */
                            p -= nlen+3;
#if 0
                            if (pkt[16] == 6 && pkt[21] == 1)
                                 snmp_pdu_add_variable(pdu, name, nlen,
                                                       SNMP_ENDOFMIBVIEW,
                                                       NULL, 0);
#endif
                            if (var == NULL) {
                                /* First OID is name OID */
                                var = snmp_add_null_var(pdu, name, nlen/sizeof(oid));
                            } else {
                                /* Second OID is value OID */
                                var->type = *p;
                                snmp_set_var_value(var, (u_char *)name, nlen);
                            }
                            free(name);
                            break;

                        case ASN_COUNTER:
                        case ASN_TIMETICKS:
                        case ASN_GAUGE:
                        case ASN_INTEGER: {
                                int32_t v;
                                v = ntohl(*((int32_t *)(p+3)));
                                var->type = *p;
                                snmp_set_var_value(var, (u_char *)&v, nlen);
                            }
                            break;

                        case ASN_OCTET_STR:
                            var->type = *p;
                            snmp_set_var_value(var, p+3, nlen);
                            break;

                        case ASN_IPADDRESS:
                            var->type = *p;
                            snmp_set_var_value(var, p+3, nlen);
                            break;

                        case ASN_NULL:
                            var->type = *p;
                            snmp_set_var_value(var, NULL, 0);
                            break;

                        default:
                            fprintf(stderr, "AAA: %d\n", *p);
                            break;
                        }
                        p += nlen+3;
                        vlen -= nlen+3;
                        payload_len -= nlen+3;
                    }
                    pdu->command = SNMP_MSG_RESPONSE;
                    rc = SNMP_ERR_NOERROR;
                }
                break;

            default:
                break;
            }
        } else {
            fprintf(stderr, "Flen: %04x\n", vlen);
            snmp_pdu_add_variable(pdu, &val, 1,
                                  ASN_OCTET_STR,
                                  p+3, vlen);
        }

        p += vlen+3;
        payload_len -= vlen+3;
    }

    return rc;
}

static int
_hook_build(netsnmp_session * sp,
            netsnmp_pdu *pdu, u_char * pkt, size_t * len)
{
    int i, k;
    int rc = 0;
    size_t offset     = 0;
    size_t sz_payload = 0;
    netsnmp_variable_list *vp;
    netsnmp_transport *transport;
    struct asmp_connection *asmp;

    transport = snmp_sess_transport(snmp_sess_pointer(sp));
    if (transport == NULL || transport->data == NULL)
        return -1;

    asmp = transport->data;

    memset(pkt, 0, 0x100);

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

    /* Fix Request ID by locally stored value */
    pdu->msgid = pdu->reqid = ++asmp->seq;
    if (asmp->seq == 0xffff)
        asmp->seq = 0;
    if (pdu->version == SNMP_VERSION_3) {
        pkt[offset++] = (pdu->msgid >> 8) & 0xff;
        pkt[offset++] =  pdu->msgid & 0xff;
    } else {
        pkt[offset++] = (pdu->reqid >> 8) & 0xff;
        pkt[offset++] =  pdu->reqid & 0xff;
    }

    pkt[offset++] =  pdu->command;
    if (asmp->proto != ASMP_PROTO_AIDP) {
        if (pdu->command == SNMP_MSG_GET)
            pkt[offset-1] = ASMP_SNMP_GET_REQUEST;
        else if (pdu->command == SNMP_MSG_GETNEXT)
            pkt[offset-1] = ASMP_SNMP_GETNEXT_REQUEST;
        else if (pdu->command == SNMP_MSG_SET)
            pkt[offset-1] = ASMP_SNMP_SET_REQUEST;
    }

    if (asmp->proto == ASMP_PROTO_AIDP &&
        pdu->command == AIDP_DISCOVER_REQUEST) {
        int v = htonl(1);
//        memcpy(pkt+offset, &v, 4);
//        offset += 4;
        v = htonl(NULL != NULL ? 29 : 6);
        memcpy(pkt+offset, &v, 4);
        offset += 4;

        pkt[offset++] = 1;
        pkt[offset++] = 0; // short
        pkt[offset++] = 2; // short
        pkt[offset++] = 1;
        pkt[offset++] = 8;

        pkt[offset++] = ASMP_FIELD_TERM;
        pkt[offset++] = ASMP_TERMINATOR;
        *len = offset;
        return rc;
    }
    /* Reserve space for payload length */
    offset += 4;

// snmp_pdu_add_variable(pdu, name, name_len, type, value, len)

    if (SNMP_CMD_CONFIRMED(pdu->command)) {
        pkt[offset] = 1;
        /* Reserve space (2 bytes) for variables' len field offset */
        for (sz_payload = offset+3, i=1, vp = pdu->variables; vp; i++, vp = vp->next_variable) {
            /* VarBind */
            pkt[sz_payload++] = 6;
            pkt[sz_payload++] = ((vp->name_length*4) >> 8) & 0xff;
            pkt[sz_payload++] =  (vp->name_length*4) & 0xff;
            /* Encode variable name */
            for (k = 0; k<vp->name_length; k++) {
                pkt[sz_payload++] = (vp->name[k] >> 24) & 0xff;
                pkt[sz_payload++] = (vp->name[k] >> 16) & 0xff;
                pkt[sz_payload++] = (vp->name[k] >>  8) & 0xff;
                pkt[sz_payload++] =  vp->name[k] & 0xff;
            }
            /* Set variable type */
            pkt[sz_payload++] = vp->type & 0xff;
            /* Encode variable */
            switch (vp->type) {
                case ASN_INTEGER: {
                        int32_t v = htonl(*vp->val.integer);
                        pkt[sz_payload++] = 0;
                        pkt[sz_payload++] = 4;
                        memcpy(pkt+sz_payload, (u_char *)&v, 4);
                        sz_payload += 4;
                    }
                    break;

                case ASN_IPADDRESS:
                    if (vp->val_len != 4) {
                        fprintf(stderr,
                                "asmp_pkt_build: ASN_IPADDRESS"
                                " is not length of 4 (%d)",
                                vp->val_len);
                        return -1;
                    }
                case ASN_OCTET_STR:
                    if (vp->val.string == NULL || *vp->val.string == '\0') {
                        memset(pkt+sz_payload, 0, 2);
                    } else {
                        uint16_t l;
                        l = htons(strlen((char *)vp->val.string));
                        memcpy(pkt+sz_payload, (u_char *)&l, 2);
                        memcpy(pkt+sz_payload+2, vp->val.string, ntohs(l));
                        sz_payload += ntohs(l);
                    }
                    sz_payload += 2;
                    break;

                case ASN_NULL:
                    memset(pkt+sz_payload, 0, 2);
                    sz_payload += 2;
                    break;

                default:
                    fprintf(stderr, "Unk: %d,%02x\n", vp->type, vp->type);
                    break;
            }
        }
        pkt[offset+1] = ((sz_payload-offset-3) >> 8) & 0xff;
        pkt[offset+2] =  (sz_payload-offset-3) & 0xff;
        /* Special case for SET command to send Username */
        if (pdu->command == SNMP_MSG_SET) {
            i = strlen(asmp->user);
            pkt[sz_payload++] = 2;
            pkt[sz_payload++] = (i >> 8) & 0xff;
            pkt[sz_payload++] =  i & 0xff;
            if (i > 0)
                memcpy(pkt+sz_payload, asmp->user, i);
            sz_payload += i;
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
    }

    /* Payload minus FIELD_TERM */
    pkt[sz_payload] = ASMP_FIELD_TERM;
    sz_payload -= offset;
    /* Move pointer to payload length field */
    offset -= 4;
    sz_payload++;
    pkt[offset++] = (sz_payload >> 24) & 0xff;
    pkt[offset++] = (sz_payload >> 16) & 0xff;
    pkt[offset++] = (sz_payload >> 8)  & 0xff;
    pkt[offset++] =  sz_payload & 0xff;
    pkt[sz_payload+offset] = ASMP_TERMINATOR;

    *len = offset+sz_payload+1;

    return rc;
}

static int
_asmp_synch_input(int op,
                 netsnmp_session * session,
                 int reqid, netsnmp_pdu *pdu, void *magic)
{
    struct synch_state *state = (struct synch_state *) magic;

    if (reqid != state->reqid)
        return 0;

    state->waiting = 0;

    if (op == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE && pdu) {
        /*
         * clone the pdu to return to snmp_synch_response.
         */
        state->pdu = snmp_clone_pdu(pdu);
        state->status = STAT_SUCCESS;
        session->s_snmp_errno = SNMPERR_SUCCESS;
    } else if (op == NETSNMP_CALLBACK_OP_TIMED_OUT) {
        state->pdu = NULL;
        state->status = STAT_TIMEOUT;
        session->s_snmp_errno = SNMPERR_TIMEOUT;
        SET_SNMP_ERROR(SNMPERR_TIMEOUT);
    } else if (op == NETSNMP_CALLBACK_OP_DISCONNECT) {
        state->pdu = NULL;
        state->status = STAT_ERROR;
        session->s_snmp_errno = SNMPERR_ABORT;
        SET_SNMP_ERROR(SNMPERR_ABORT);
    }

    return 1;
}
