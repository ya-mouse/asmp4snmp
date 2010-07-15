#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <net-snmp/library/asn1.h>

#include "session.h"

int
asmp_request(struct asmp_cfg *cfg, uint8_t cmd, uint32_t len, const uint8_t *data)
{
    uint8_t  resp;
    uint8_t *req;
    uint32_t sz;

    cfg->seq++;
    sz  = htonl(len);
    req = calloc(1, 13+len);
    req[0]  = ASMP_SOH;
    memcpy(req+1, "ASMP", 4);
    req[5]  = (cfg->seq >> 8) & 0xff;
    req[6]  =  cfg->seq & 0xff;
    req[7]  = cmd;
    memcpy(req+8, &sz, 4);
    memcpy(req+12, data, len);
    req[12+len] = ASMP_TERMINATOR;
    cfg->meth->write(cfg, req, 13+len);

    cfg->meth->read(cfg, &resp, 1);
    printf("Resp: %x\n", resp);

    return resp;
}
