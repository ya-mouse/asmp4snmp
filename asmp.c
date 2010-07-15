#include <string.h>
#include <stdlib.h>

#include <stdio.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "asmp.h"
#include "network.h"
#include "session.h"

int
main(int argc, char *argv[])
{
    int status;
    struct asmp_cfg cfg;

    if (argc != 2)
        return 1;
    memset(&cfg, 0, sizeof(cfg));

    SSL_library_init();

    cfg.timeout = 5000;
    status = asmp_net_connect(&cfg, argv[1], 3211);
    if (status != 0) {
        fprintf(stderr, "Connection to %s:%d failed\n", argv[1], 3211);
        goto close;
    }

close:
    close(cfg.tcp_sock);
    return status;
}
