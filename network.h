#ifndef _ASMP_NETWORK
#define _ASMP_NETWORK

#include "asmp.h"

struct asmp_pdu *asmp_pdu_new(const uint8_t cmd, const void *buf, int len);
void             asmp_pdu_free(struct asmp_pdu *pdu);

int              asmp_net_connect(struct asmp_cfg *cfg, const char *host, int port);
int              asmp_net_login(struct asmp_cfg *cfg, const char *user, const char *passwd);

#endif
