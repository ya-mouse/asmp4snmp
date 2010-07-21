#ifndef _ASMP_SES
#define _ASMP_SES

#include "asmp.h"

netsnmp_session *asmp_open(netsnmp_session *in_session);

int asmp_sess_setup(netsnmp_session *session);
int asmp_sess_login(netsnmp_session *session,
                    const char *user, const char *passwd);
int asmp_sess_logout(netsnmp_session *session);

#endif
