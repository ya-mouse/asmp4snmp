#include <stdio.h>
#define __USE_GNU
#include <dlfcn.h>
#undef  __USE_GNU

#include "asmp.h"
#include "session.h"

static netsnmp_session * (*next_snmp_open)(netsnmp_session *session) = NULL;

netsnmp_session *
snmp_open(netsnmp_session *in_session)
{
    netsnmp_session   *session;

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
        netsnmp_aidp_ctor();
    }

    session = asmp_open(in_session);
    if (session == NULL)
        session = next_snmp_open(in_session);

    return session;
}
