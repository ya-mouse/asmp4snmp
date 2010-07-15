#ifndef _ASMP_SES
#define _ASMP_SES

#include "asmp.h"

int asmp_request(struct asmp_cfg *cfg, const struct asmp_pdu *pdu, struct asmp_pdu **response);

#endif
