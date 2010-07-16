#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <net-snmp/library/asn1.h>

#include "session.h"

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

    xdump(pdu->data, pdu->len, ">> ");

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
    printf("[%02x][%02x][%04x]\n", resp->seq, resp->cmd, resp->len);
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
