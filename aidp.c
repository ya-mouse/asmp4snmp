#include "asmp.h"
#include "session.h"

int main(int argc, char *argv[])
{
    netsnmp_session session;

    netsnmp_aidp_ctor();

    switch (arg = snmp_parse_args(argc, argv, &session, NULL, NULL)) {
    case -2:
        exit(0);
    case -1:
        exit(1);
    default:
        break;
    }

    session = asmp_open(&session);
    if (session == NULL)
        return -1;


    return 0;
}
