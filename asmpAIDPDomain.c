#include "asmp.h"

#include <net-snmp/types.h>
#include <net-snmp/output_api.h>

#include <net-snmp/library/snmp_transport.h>

oid netsnmp_asmpAIDPDomain[] = { TRANSPORT_DOMAIN_AIDP };
static netsnmp_tdomain asmpDomain;

netsnmp_transport *netsnmp_udp_create_tstring();
netsnmp_transport *netsnmp_udp_create_ostring();

void
netsnmp_aidp_ctor(void)
{
    asmpDomain.name = netsnmp_asmpAIDPDomain;
    asmpDomain.name_length = sizeof(netsnmp_asmpAIDPDomain) / sizeof(oid);
    asmpDomain.prefix = (const char **)calloc(2, sizeof(char *));
    asmpDomain.prefix[0] = "aidp";

    asmpDomain.f_create_from_tstring_new = netsnmp_udp_create_tstring;
    asmpDomain.f_create_from_ostring = netsnmp_udp_create_ostring;

    netsnmp_tdomain_register(&asmpDomain);
}
