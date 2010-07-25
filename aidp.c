#include "asmp.h"
#include "session.h"

static int _discovery_ipv6();

int main(int argc, char *argv[])
{
    int              arg;
    netsnmp_session  session;
    netsnmp_session *ss;

    netsnmp_aidp_ctor();

    switch (arg = snmp_parse_args(argc, argv, &session, NULL, NULL)) {
    case -2:
        exit(0);
    case -1:
        exit(1);
    default:
        break;
    }

    ss = asmp_open(&session);
    if (ss == NULL)
        return -1;

    _discovery_ipv6(ss);

    return 0;
}

static int
_discovery_ipv6(netsnmp_session *session)
{
    int rc;
    netsnmp_pdu *pdu;
    netsnmp_pdu *response;
    netsnmp_variable_list *vars;

    pdu = snmp_pdu_create(AIDP_DISCOVER_REQUEST);

    rc = asmp_synch_response(session, pdu, &response);
    if (rc != STAT_SUCCESS)
        goto free;

    for (vars = response->variables; vars; vars = vars->next_variable) {
        switch (*vars->name) {
        case 1: /* Model */
            fprintf(stderr, "Model: %02x\n", ntohs(*((uint16_t *)vars->val.string)));
            break;

        case 2: /* MAC */
            fprintf(stderr, "MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    vars->val.string[0], vars->val.string[1], vars->val.string[2],
                    vars->val.string[3], vars->val.string[4], vars->val.string[5]);
            break;

        case 3: /* IP */
            break;

        case 4: /* Subnet mask */
            break;

        case 5: /* Gateway */
            break;

        case 6: /* Hostname */
            break;

        case 7: /* Supported modes */
            fprintf(stderr, "Supported modes: %02x\n", *vars->val.string);
            break;

        default:
            break;
        }
    }

    snmp_free_pdu(response);

    snmp_free_pdu(pdu);

free:
    return rc;
}
