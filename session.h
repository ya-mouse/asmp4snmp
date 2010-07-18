#ifndef _ASMP_SES
#define _ASMP_SES

#include "asmp.h"

int asmp_close(netsnmp_session *session);
netsnmp_session *asmp_open(netsnmp_session *in_session);
int asmp_request(struct asmp_cfg *cfg, const struct asmp_pdu *pdu, struct asmp_pdu **response);

#endif
