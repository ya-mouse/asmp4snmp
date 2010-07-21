#ifndef _ASMP_SES
#define _ASMP_SES

#include "asmp.h"

netsnmp_session *asmp_open(netsnmp_session *in_session);

int asmp_sess_setup(netsnmp_session *session);
int asmp_sess_login(netsnmp_session *session,
                    const char *user, const char *passwd);


int asmp_request(struct asmp_cfg *cfg, const struct asmp_pdu *pdu, struct asmp_pdu **response);

#endif
