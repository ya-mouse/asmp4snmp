#ifndef _ASMP_NETWORK
#define _ASMP_NETWORK

#include "asmp.h"

struct asmp_pdu *asmp_pdu_new(const uint8_t cmd, const void *buf, int len);
void             asmp_pdu_free(struct asmp_pdu *pdu);

int              asmp_net_connect(struct asmp_cfg *cfg);
int              asmp_net_login(struct asmp_cfg *cfg, const char *user, const char *passwd);
int              asmp_net_logout(struct asmp_cfg *cfg);

int asmp_request(struct asmp_cfg *cfg, const struct asmp_pdu *pdu, struct asmp_pdu **response);

#endif
