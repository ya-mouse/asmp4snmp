#include "asmp.h"

#include <net-snmp/types.h>
#include <net-snmp/output_api.h>

#include <net-snmp/library/snmp_transport.h>

oid netsnmp_asmpTCPDomain[] = { 1,3,6,1,2,1,100,1,10418,0 };
static netsnmp_tdomain asmpDomain;

void
netsnmp_asmp_ctor(void)
{
    asmpDomain.name = netsnmp_asmpTCPDomain;
    asmpDomain.name_length = sizeof(netsnmp_asmpTCPDomain) / sizeof(oid);
    asmpDomain.prefix = (const char **)calloc(2, sizeof(char *));
    asmpDomain.prefix[0] = "asmp";

    //asmpDomain.f_create_from_tstring_new = netsnmp_tcp_create_tstring;
    //asmpDomain.f_create_from_ostring = netsnmp_tcp_create_ostring;

    netsnmp_tdomain_register(&asmpDomain);
}
