#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "asmp.h"

#include <openssl/rand.h>

#include <net-snmp/types.h>
#include <net-snmp/output_api.h>

#include <net-snmp/library/snmp_transport.h>

int netsnmp_sockaddr_in2();

oid netsnmp_asmpASMPDomain[]  = { TRANSPORT_DOMAIN_ASMP };
oid netsnmp_asmpASMPSDomain[] = { TRANSPORT_DOMAIN_ASMPS };

static netsnmp_tdomain asmpASMPDomain;
static netsnmp_tdomain asmpASMPSDomain;

static int _tcp_send();
static int _tcp_recv();
static int _ssl_send();
static int _ssl_recv();
static int _dsr_asmp_version();
static int _setup_ssl();

// t->sock, buf, size, 0

static struct asmpnet_meth tcp_connection = {
    .send  = _tcp_send,
    .recv  = _tcp_recv
};

static struct asmpnet_meth ssl_connection = {
    .send  = _ssl_send,
    .recv  = _ssl_recv
};

#if 0
/*
 * Return a string representing the address in data, or else the "far end"
 * address if data is NULL.  
 */

static char *
_td_tcp_fmtaddr(netsnmp_transport *t, void *data, int len)
{
    netsnmp_udp_addr_pair *addr_pair = NULL;

    if (data != NULL && len == sizeof(netsnmp_udp_addr_pair)) {
	addr_pair = (netsnmp_udp_addr_pair *) data;
    } else if (t != NULL && t->data != NULL) {
	addr_pair = (netsnmp_udp_addr_pair *) t->data;
    }

    if (addr_pair == NULL) {
        return strdup("TCP: unknown");
    } else {
        struct sockaddr_in *to = NULL;
	char tmp[64];
        to = (struct sockaddr_in *) &(addr_pair->remote_addr);
        if (to == NULL) {
            return strdup("TCP: unknown");
        }

        sprintf(tmp, "TCP: [%s]:%hd",
                inet_ntoa(to->sin_addr), ntohs(to->sin_port));
        return strdup(tmp);
    }
}
#endif



/*
 * You can write something into opaque that will subsequently get passed back 
 * to your send function if you like.  For instance, you might want to
 * remember where a PDU came from, so that you can send a reply there...  
 */

static int
_td_tcp_recv(netsnmp_transport *t, void *buf, int size,
		 void **opaque, int *olength)
{
    int rc = -1;

    if (t != NULL && t->sock >= 0) {
        struct asmp_connection *asmp = (struct asmp_connection *)t->data;
	while (rc < 0) {
	    rc = asmp->meth->recv(asmp, buf, size);
	    if (rc < 0 && errno != EINTR) {
		DEBUGMSGTL(("netsnmp_tcp", "recv fd %d err %d (\"%s\")\n",
			    t->sock, errno, strerror(errno)));
		break;
	    }
	    DEBUGMSGTL(("netsnmp_tcp", "recv fd %d got %d bytes\n",
			t->sock, rc));
	}
    } else {
        return -1;
    }

#if 0
    if (opaque != NULL && olength != NULL) {
        if (t->data_length > 0) {
            if ((*opaque = malloc(t->data_length)) != NULL) {
                memcpy(*opaque, t->data, t->data_length);
                *olength = t->data_length;
            } else {
                *olength = 0;
            }
        } else {
            *opaque = NULL;
            *olength = 0;
        }
    }
#endif

    return rc;
}

static int
_td_tcp_send(netsnmp_transport *t, void *buf, int size,
		 void **opaque, int *olength)
{
    int rc = -1;

    if (t != NULL && t->sock >= 0) {
        struct asmp_connection *asmp = (struct asmp_connection *)t->data;
	while (rc < 0) {
	    rc = asmp->meth->send(asmp, buf, size);
	    if (rc < 0 && errno != EINTR) {
		break;
	    }
	}
    }
    return rc;
}

static int
_td_tcp_close(netsnmp_transport *t)
{
    int rc = -1;
    if (t != NULL && t->sock >= 0) {
        struct asmp_connection *con = (struct asmp_connection *)t->data;
        // TODO: ASMP_LOGOUT

        if (con->proto == ASMP_PROTO_ASMPS) {
            if (con->ssl_sock != NULL) {
                SSL_shutdown(con->ssl_sock);
                SSL_set_connect_state(con->ssl_sock);
                SSL_free(con->ssl_sock);
            }
            if (con->ssl_ctx != NULL)
                SSL_CTX_free(con->ssl_ctx);
        }

        DEBUGMSGTL(("netsnmp_tcp", "close fd %d\n", t->sock));
#ifndef HAVE_CLOSESOCKET
        rc = close(t->sock);
#else
        rc = closesocket(t->sock);
#endif
        t->sock = -1;
    }
    return rc;
}

static int
_tcp_send(struct asmp_connection *con, const void *buf, int num)
{
    return send(con->tcp_sock, buf, num, 0);
}

static int
_tcp_recv(struct asmp_connection *con, void *buf, int num)
{
    return recv(con->tcp_sock, buf, num, 0);
}

static int
_ssl_send(struct asmp_connection *con, const void *buf, int num)
{
    return SSL_write(con->ssl_sock, buf, num);
}

static int
_ssl_recv(struct asmp_connection *con, void *buf, int num)
{
    return SSL_read(con->ssl_sock, buf, num);
}

static netsnmp_transport *
_create_tstring(oid *domain, int domain_len, int proto,
                const char *str, int local,
                const char *default_target)
{
    int rc;
    netsnmp_transport *t = NULL;
    struct asmp_connection *asmp;
    struct sockaddr_in addr;

    if (!netsnmp_sockaddr_in2(&addr, str, default_target))
        return NULL;

    if (addr.sin_family != AF_INET)
        return NULL;

    t = (netsnmp_transport *) calloc(1, sizeof(netsnmp_transport));
    if (t == NULL)
        return NULL;

#if 0
    addr_pair = (netsnmp_udp_addr_pair *)malloc(sizeof(netsnmp_udp_addr_pair));
    if (addr_pair == NULL)
        goto free;
    t->data = addr_pair;
    t->data_length = sizeof(netsnmp_udp_addr_pair);
    memcpy(&(addr_pair->remote_addr), addr, sizeof(struct sockaddr_in));
#else
    asmp = calloc(1, sizeof(struct asmp_connection));
    t->data = asmp;
    t->data_length = sizeof(struct asmp_connection);
#endif

    t->domain = domain;
    t->domain_length = domain_len;

    t->sock = socket(PF_INET, SOCK_STREAM, 0);
    if (t->sock < 0)
        goto free;

    t->flags = NETSNMP_TRANSPORT_FLAG_STREAM;

    if (local) {
        int sockflags = 0, opt = 1;

        /*
         * This session is inteneded as a server, so we must bind to the given 
         * IP address (which may include an interface address, or could be
         * INADDR_ANY, but will always include a port number.  
         */

        t->flags |= NETSNMP_TRANSPORT_FLAG_LISTEN;
        t->local = (u_char *)malloc(6);
        if (t->local == NULL)
            goto free;
        memcpy(t->local, (u_char *) & (addr.sin_addr.s_addr), 4);
        t->local[4] = (htons(addr.sin_port) & 0xff00) >> 8;
        t->local[5] = (htons(addr.sin_port) & 0x00ff) >> 0;
        t->local_length = 6;

        /*
         * We should set SO_REUSEADDR too.  
         */

        setsockopt(t->sock, SOL_SOCKET, SO_REUSEADDR, (void *)&opt,
                   sizeof(opt));

        rc = bind(t->sock, (struct sockaddr *)&addr, sizeof(struct sockaddr));
        if (rc != 0)
            goto free;

        /*
         * Since we are going to be letting select() tell us when connections
         * are ready to be accept()ed, we need to make the socket n0n-blocking
         * to avoid the race condition described in W. R. Stevens, ``Unix
         * Network Programming Volume I Second Edition'', pp. 422--4, which
         * could otherwise wedge the agent.
         */

#ifdef WIN32
        opt = 1;
        ioctlsocket(t->sock, FIONBIO, &opt);
#else
        sockflags = fcntl(t->sock, F_GETFL, 0);
        fcntl(t->sock, F_SETFL, sockflags | O_NONBLOCK);
#endif

        /*
         * Now sit here and wait for connections to arrive.  
         */

        rc = listen(t->sock, NETSNMP_STREAM_QUEUE_LEN);
        if (rc != 0)
            goto free;
        /*
         * no buffer size on listen socket - doesn't make sense
         */
    } else {
        t->remote = (u_char *)malloc(6);
        if (t->remote == NULL)
            goto free;

        memcpy(t->remote, (u_char *) & (addr.sin_addr.s_addr), 4);
        t->remote[4] = (htons(addr.sin_port) & 0xff00) >> 8;
        t->remote[5] = (htons(addr.sin_port) & 0x00ff) >> 0;
        t->remote_length = 6;

        /*
         * This is a client-type session, so attempt to connect to the far
         * end.  We don't go non-blocking here because it's not obvious what
         * you'd then do if you tried to do snmp_sends before the connection
         * had completed.  So this can block.
         */

        rc = connect(t->sock, (struct sockaddr *)&addr,
                     sizeof(struct sockaddr));

        if (rc < 0)
            goto free;

        /*
         * Allow user to override the send and receive buffers. Default is
         * to use os default.  Don't worry too much about errors --
         * just plough on regardless.  
         */
        netsnmp_sock_buffer_set(t->sock, SO_SNDBUF, local, 0);
        netsnmp_sock_buffer_set(t->sock, SO_RCVBUF, local, 0);
    }

    /*
     * Message size is not limited by this transport (hence msgMaxSize
     * is equal to the maximum legal size of an SNMP message).  
     */

    t->msgMaxSize = 0x7fffffff;
    t->f_recv     = _td_tcp_recv;
    t->f_send     = _td_tcp_send;
    t->f_close    = _td_tcp_close;
    t->f_accept   = NULL;
    t->f_fmtaddr  = NULL; // _td_tcp_fmtaddr;

    asmp->tcp_sock = t->sock;
    asmp->proto    = proto;
    asmp->meth     = &tcp_connection;

    // TODO: ASMP_SETUP_REQUEST

    if (asmp->proto == ASMP_PROTO_ASMPS) {
        if (_setup_ssl(asmp) < 0)
            goto free;
    }

    _dsr_asmp_version(asmp);

    goto exit;

free:
    if (t->sock >= 0)
        _td_tcp_close(t);
    netsnmp_transport_free(t);
    t = NULL;

exit:

    return t;
}

static int
_dsr_asmp_version(struct asmp_connection *con)
{
    int rc = 0;

#if 0
    struct asmp_pdu *pdu;
    struct asmp_pdu *response = NULL;
    uint8_t req[] = {ASMP_SOH, 0, 3, '3', '.', '0', ASMP_FIELD_TERM};

    pdu = asmp_pdu_new(ASMP_VERSION_REQUEST, req, sizeof(req));
    if (asmp_request(cfg, pdu, &response) != 0 || response == NULL) {
        rc = -1;
        goto free;
    }

    /* TODO: collect DSR version from response */

    asmp_pdu_free(response);
    rc = 0;

free:
    asmp_pdu_free(pdu);
#endif

    return rc;
}

static int
_setup_ssl(struct asmp_connection *con)
{
    int rc = -1;

    RAND_status();
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_all_algorithms();
    SSLeay_add_ssl_algorithms();

    con->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (con->ssl_ctx == NULL) {
        fprintf(stderr, "asmp_ASMPDomain: Couldn't create SSL context\n");
        goto exit;
    }
    SSL_CTX_set_default_verify_paths(con->ssl_ctx);

    /* SSL_VERIFY_NONE instructs OpenSSL not to abort SSL_connect if the
       certificate is invalid.  We verify the certificate separately in
       ssl_check_certificate, which provides much better diagnostics
       than examining the error stack after a failed SSL_connect.  */
    SSL_CTX_set_verify (con->ssl_ctx, SSL_VERIFY_NONE, NULL);

    /* Since fd_write unconditionally assumes partial writes (and
       handles them correctly), allow them in OpenSSL.  */
    SSL_CTX_set_mode(con->ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

    /* The OpenSSL library can handle renegotiations automatically, so
       tell it to do so.  */
    SSL_CTX_set_mode(con->ssl_ctx, SSL_MODE_AUTO_RETRY);

    con->ssl_sock = SSL_new(con->ssl_ctx);
    if (con->ssl_sock == NULL) {
        fprintf(stderr, "asmp_ASMPDomain: Coulnd't create SSL\n");
        goto exit;
    }

    SSL_set_fd(con->ssl_sock, con->tcp_sock);
    SSL_set_connect_state(con->ssl_sock);

    if (SSL_connect(con->ssl_sock) <= 0 || con->ssl_sock->state != SSL_ST_OK) {
        fprintf(stderr,
                "asmp_ASMPDomain: Coulnd't establish SSL connection with remote host\n");
            goto exit;
    }

    con->meth = &ssl_connection;
    rc = 0;

exit:
    return rc;
}

static netsnmp_transport *
_asmp_create_tstring(const char *str, int local,
                     const char *default_target)
{
    return _create_tstring(netsnmp_asmpASMPDomain,
                           sizeof(netsnmp_asmpASMPDomain)/sizeof(oid),
                           ASMP_PROTO_ASMP,
                           str, local, default_target);
}

static netsnmp_transport *
_asmps_create_tstring(const char *str, int local,
                      const char *default_target)
{
    return _create_tstring(netsnmp_asmpASMPSDomain,
                           sizeof(netsnmp_asmpASMPSDomain)/sizeof(oid),
                           ASMP_PROTO_ASMPS,
                           str, local, default_target);
}

static netsnmp_transport *
_create_ostring(const u_char * o, size_t o_len, int local)
{
    return NULL;
}

void
netsnmp_asmp_ctor(void)
{
    asmpASMPDomain.name = netsnmp_asmpASMPDomain;
    asmpASMPDomain.name_length = sizeof(netsnmp_asmpASMPDomain) / sizeof(oid);
    asmpASMPDomain.prefix = (const char **)calloc(2, sizeof(char *));
    asmpASMPDomain.prefix[0] = "asmp";

    asmpASMPDomain.f_create_from_tstring_new = _asmp_create_tstring;
    asmpASMPDomain.f_create_from_ostring = _create_ostring;

    netsnmp_tdomain_register(&asmpASMPDomain);

    asmpASMPSDomain.name = netsnmp_asmpASMPSDomain;
    asmpASMPSDomain.name_length = sizeof(netsnmp_asmpASMPSDomain) / sizeof(oid);
    asmpASMPSDomain.prefix = (const char **)calloc(2, sizeof(char *));
    asmpASMPSDomain.prefix[0] = "asmps";

    asmpASMPSDomain.f_create_from_tstring_new = _asmps_create_tstring;
    asmpASMPSDomain.f_create_from_ostring = _create_ostring;

    netsnmp_tdomain_register(&asmpASMPSDomain);
}
