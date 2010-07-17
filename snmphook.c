#include <stdio.h>
#define __USE_GNU
#include <dlfcn.h>
#undef  __USE_GNU

#include "asmp.h"

void netsnmp_asmp_ctor();

static netsnmp_session * (*next_snmp_open)(netsnmp_session *session) = NULL;

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

    fprintf(stderr, "_hook_build called\n");
    rc = snmp_build(&pkt, len, &offset, sp, pdu);
    if (rc >= 0) {
        memcpy(pkt, pkt+(*len)-offset, *len);
        *len = offset;
    }
    return rc;
}

netsnmp_session *
snmp_open(netsnmp_session *in_session)
{
    netsnmp_session   *session;
    netsnmp_transport *transport;

    fprintf(stderr, "Hooked snmp_open called\n");
    if (next_snmp_open == NULL) {
        char *msg;

        next_snmp_open = dlsym(RTLD_NEXT, "snmp_open");
        if ((msg = dlerror()) != NULL) {
            fprintf(stderr, "snmp_open: dlopen failed : %s\n", msg);
            fflush(stderr);
            return NULL;
        }

        /* Register ASMP Domains */
        netsnmp_asmp_ctor();
    }

    if (in_session == NULL)
        return NULL;

    if (in_session->version == SNMP_VERSION_3 &&
        (!strncmp(in_session->peername, "asmp:", 5) ||
         !strncmp(in_session->peername, "asmps:", 6) ||
         !strncmp(in_session->peername, "aidp:", 5)))
    {
        /* Set TCP flag for non-AIDP connection */
        if (strncmp(in_session->peername, "aidp:", 5))
            in_session->flags |= SNMP_FLAGS_STREAM_SOCKET;

        if (in_session->flags & SNMP_FLAGS_STREAM_SOCKET) {
            transport =
                netsnmp_tdomain_transport_full("snmp", in_session->peername,
                                               session->local_port, "tcp",
                                               NULL);
        } else {
            transport =
                netsnmp_tdomain_transport_full("snmp", in_session->peername,
                                               session->local_port, "udp",
                                               NULL);
        }

        session = snmp_add_full(in_session,
                            transport,
                            NULL, _hook_parse,
                            NULL, _hook_build,
                            NULL, NULL,
                            NULL);
        if (session != NULL)
            fprintf(stderr, "Hook installed\n");
    } else {
        session = next_snmp_open(in_session);
        fprintf(stderr, "SNMPv is not 3. Hook NOT installed\n");
    }

    return session;
}
