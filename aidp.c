#include "asmp.h"
#include "session.h"

#include "aidp.h"

/*
 *  ff02::ffff
 *  ff08::ffff
 *  ff0e::ffff
 */

static struct aidp_disc_info *_discovery_ipv6();
static int _configure_ip();

int main(int argc, char *argv[])
{
    int              arg;
    netsnmp_session  session;
    netsnmp_session *ss;
    struct aidp_disc_info *info;

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

    info = _discovery_ipv6(ss);
    if (info == NULL)
        return -2;

    info->ip[0] = 95;
    info->ip[1] = 108;
    info->ip[2] = 178;
    info->ip[3] = 154;
    info->mask[0] = 0xff;
    info->mask[1] = 0xff;
    info->mask[2] = 0xff;
    info->mask[3] = 0;
    info->gw[0] = 95;
    info->gw[1] = 108;
    info->gw[2] = 178;
    info->gw[3] = 158;

    _configure_ip(ss, info, 4);

    return 0;
}

static struct aidp_disc_info *
_discovery_ipv6(netsnmp_session *session)
{
    int rc;
    netsnmp_pdu *pdu;
    netsnmp_pdu *response;
    netsnmp_variable_list *vars;
    struct aidp_disc_info *info = NULL;

    pdu = snmp_pdu_create(AIDP_DISCOVER_REQUEST);

    rc = asmp_synch_response(session, pdu, &response);
    if (rc != STAT_SUCCESS)
        goto free;

    info = calloc(1, sizeof(struct aidp_disc_info));

    for (vars = response->variables; vars; vars = vars->next_variable) {
        switch (*vars->name) {
        case 1: /* Model */
            info->model = ntohs(*((uint16_t *)vars->val.string));
            fprintf(stderr, "Model: %02x\n", info->model);
            break;

        case 2: /* MAC */
            memcpy(info->mac, vars->val.string, 6);
            fprintf(stderr, "MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    info->mac[0], info->mac[1], info->mac[2],
                    info->mac[3], info->mac[4], info->mac[5]);
            break;

        case 3: /* IP */
            memcpy(info->ip, vars->val.string, 4);
            break;

        case 4: /* Subnet mask */
            memcpy(info->mask, vars->val.string, 4);
            break;

        case 5: /* Gateway */
            memcpy(info->gw, vars->val.string, 4);
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
    return info;
}

static int
_configure_ip(netsnmp_session *session, struct aidp_disc_info *info, int mode)
{
    int rc;
    int v;
    oid val = 0;
    netsnmp_pdu *pdu;
    netsnmp_pdu *response;

    pdu = snmp_pdu_create(AIDP_TEST_IP_REQUEST);
    snmp_pdu_add_variable(pdu, &val, 1,
                          ASN_OCTET_STR,
                          info->mac, 6);
    snmp_pdu_add_variable(pdu, &val, 1,
                          ASN_OCTET_STR,
                          info->ip, 4);
    if ((mode & 4) == 4) {
        v = 64;
        snmp_pdu_add_variable(pdu, &val, 1,
                              ASN_OCTET_STR,
                              (unsigned char *)&v, 1);
    } else {
        snmp_pdu_add_variable(pdu, &val, 1,
                              ASN_OCTET_STR,
                              info->mask, 4);
    }
    snmp_pdu_add_variable(pdu, &val, 1,
                          ASN_OCTET_STR,
                          info->gw, 4);
    if ((mode & 4) == 4) {
        snmp_pdu_add_variable(pdu, &val, 1,
                              ASN_OCTET_STR,
                              (unsigned char *)&mode, 1);
    }

    rc = asmp_synch_response(session, pdu, &response);
    if (rc != STAT_SUCCESS)
        goto free;

    fprintf(stderr, "Done\n");

free:
    return rc;
}
