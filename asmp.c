#include <string.h>
#include <stdlib.h>

#include <stdio.h>
#include <unistd.h>

#include <openssl/rand.h>

#include "asmp.h"
#include "network.h"
#include "session.h"

int
main(int argc, char *argv[])
{
    int status;
    struct asmp_cfg cfg;

    if (argc < 2)
        return 1;
    memset(&cfg, 0, sizeof(cfg));

    RAND_status();
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_all_algorithms();
    SSLeay_add_ssl_algorithms();

    cfg.timeout = 5000;
    cfg.is_ssl  = argc == 3 ? 1 : 0;
    cfg.host    = strdup(argv[1]);
    cfg.port    = 3211;
    status = asmp_net_connect(&cfg);
    if (status != 0) {
        fprintf(stderr, "Connection to %s:%d failed\n", cfg.host, cfg.port);
        goto close;
    }

    asmp_net_logout(&cfg);

close:
    close(cfg.tcp_sock);
    return status;
}
