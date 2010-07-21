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
asmp_sess_logout(netsnmp_session *session)
{
    netsnmp_pdu *pdu;
    netsnmp_pdu *response;

    pdu = snmp_pdu_create(ASMP_LOGOUT_REQUEST);

    return snmp_synch_response(session, pdu, &response);
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
    int i, k;
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
    offset += 2;

// snmp_pdu_add_variable(pdu, name, name_len, type, value, len)

    if (SNMP_CMD_CONFIRMED(pdu->command)) {
        for (sz_payload = offset, i=0, vp = pdu->variables; vp; i++, vp = vp->next_variable) {
            pkt[sz_payload++] = i & 0xff;
            /* Save variable's len field offset */
            pkt[sz_payload++] = (vp->name_length >> 8) & 0xff;
            pkt[sz_payload++] =  vp->name_length & 0xff;
            /* Encode variable name */
            fprintf(stderr, "Requesting OID: ");
            for (k = 0; i<vp->name_length; k++) {
                pkt[sz_payload++] = (vp->name[k] >> 24) & 0xff;
                pkt[sz_payload++] = (vp->name[k] >> 16) & 0xff;
                pkt[sz_payload++] = (vp->name[k] >>  8) & 0xff;
                pkt[sz_payload++] =  vp->name[k] & 0xff;
                fprintf(stderr, ".%d", (int)vp->name[k]);
            }
            fprintf(stderr, "\n");
            /* Set variable type */
            pkt[sz_payload++] = vp->type & 0xff;
            /* Encode variable */
            switch (vp->type) {
                case ASN_INTEGER:
                    break;

                case ASN_OCTET_STR:
                    break;

                case ASN_NULL:
                    memset(pkt+sz_payload, 0, 2);
                    sz_payload += 2;
                    break;
            }
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
    pkt[sz_payload++] = ASMP_FIELD_TERM;
    /* Payload minus FIELD_TERM */
    sz_payload -= offset+1;
    /* Move pointer to payload length field */
    offset -= 2;
    pkt[offset++] = (sz_payload >> 8) & 0xff;
    pkt[offset++] =  sz_payload & 0xff;
    pkt[sz_payload+(offset++)+1] = ASMP_TERMINATOR;

    *len = offset+sz_payload+1;

    return rc;
}
