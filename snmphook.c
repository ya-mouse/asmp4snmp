#include <stdio.h>
#define __USE_GNU
#include <dlfcn.h>
#undef  __USE_GNU

#define SNMP_NEED_REQUEST_LIST
#include "asmp.h"

/*                             Part of snmp_api.c
 * ============================================================================
 */

/*
 * Internal information about the state of the snmp session.
 */
struct snmp_internal_session {
    netsnmp_request_list *requests;     /* Info about outstanding requests */
    netsnmp_request_list *requestsEnd;  /* ptr to end of list */
    int             (*hook_pre) (netsnmp_session *, netsnmp_transport *,
                                 void *, int);
    int             (*hook_parse) (netsnmp_session *, netsnmp_pdu *,
                                   u_char *, size_t);
    int             (*hook_post) (netsnmp_session *, netsnmp_pdu *, int);
    int             (*hook_build) (netsnmp_session *, netsnmp_pdu *,
                                   u_char *, size_t *);
    int             (*hook_realloc_build) (netsnmp_session *,
                                           netsnmp_pdu *, u_char **,
                                           size_t *, size_t *);
    int             (*check_packet) (u_char *, size_t);
    netsnmp_pdu    *(*hook_create_pdu) (netsnmp_transport *,
                                        void *, size_t);

    u_char         *packet;
    size_t          packet_len, packet_size;
};

struct session_list {
    struct session_list *next;
    netsnmp_session *session;
    netsnmp_transport *transport;
    struct snmp_internal_session *internal;
};

int             snmp_build(u_char ** pkt, size_t * pkt_len,
                           size_t * offset, netsnmp_session * pss,
                           netsnmp_pdu *pdu);

/* ============================================================================
 *                        End of Part of snmp_api.c
 */

static netsnmp_session * (*next_snmp_open)(netsnmp_session *session) = NULL;

static int
_hook_build(netsnmp_session * sp,
                            netsnmp_pdu *pdu, u_char * pkt, size_t * len)
{
    size_t offset = 0;
    fprintf(stderr, "_hook_build called: %d\n", *len);
    int rc = snmp_build(&pkt, len, &offset, sp, pdu);
    fprintf(stderr, "_hook_build offset=%d %d\n", offset, *len);
    if (rc >= 0) {
        memcpy(pkt, pkt+(*len)-offset, *len);
        *len = offset;
    }
    return rc;
}

netsnmp_session *
snmp_open(netsnmp_session *in_session)
{
    struct session_list *slp;
    netsnmp_session *session;

    fprintf(stderr, "Hooked snmp_open called\n");
    if (next_snmp_open == NULL)
    {
      char *msg;

      next_snmp_open = dlsym(RTLD_NEXT, "snmp_open");
      if ((msg = dlerror()) != NULL)
      {
         fprintf(stderr, "snmp_open: dlopen failed : %s\n", msg);
         fflush(stderr);
         exit(1);
      }
    }

    if ((session = next_snmp_open(in_session)) == NULL)
        return NULL;

    if ((slp = (struct session_list *) snmp_sess_pointer(session)) == NULL)
        return NULL;

    slp->internal->hook_build = _hook_build;
    fprintf(stderr, "Hook installed\n");

    return session;
}
