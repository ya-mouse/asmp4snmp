#include <stdlib.h>
#include <errno.h>

#include "asmp.h"

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
    .send = _tcp_send,
    .recv = _tcp_recv
};

static struct asmpnet_meth ssl_connection = {
    .send = _ssl_send,
    .recv = _ssl_recv
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
_create_tstring(oid *domain, int domain_len, int is_asmps,
                const char *str, int local,
                const char *default_target)
{
    int rc;
    netsnmp_transport *t = NULL;
    struct asmp_connection *asmp;
    struct sockaddr_in addr;

    if (local) {
        /* Server mode is not supported */
        return NULL;
    }

    if (!netsnmp_sockaddr_in2(&addr, str, default_target))
        return NULL;

    if (addr.sin_family != AF_INET)
        return NULL;

    t = (netsnmp_transport *) calloc(1, sizeof(netsnmp_transport));
    if (t == NULL)
        return NULL;

#if 0
    addr_pair = (netsnmp_udp_addr_pair *)malloc(sizeof(netsnmp_udp_addr_pair));
    if (addr_pair == NULL) {
        netsnmp_transport_free(t);
        return NULL;
    }
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
    if (t->sock < 0) {
        netsnmp_transport_free(t);
        return NULL;
    }

    t->flags = NETSNMP_TRANSPORT_FLAG_STREAM;

    t->remote = (u_char *)malloc(6);
    if (t->remote == NULL) {
        _td_tcp_close(t);
        netsnmp_transport_free(t);
        return NULL;
    }
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

    if (rc < 0) {
        _td_tcp_close(t);
        netsnmp_transport_free(t);
        return NULL;
    }

    /*
     * Allow user to override the send and receive buffers. Default is
     * to use os default.  Don't worry too much about errors --
     * just plough on regardless.  
     */
    netsnmp_sock_buffer_set(t->sock, SO_SNDBUF, local, 0);
    netsnmp_sock_buffer_set(t->sock, SO_RCVBUF, local, 0);

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
    asmp->is_asmps = is_asmps;
    if (is_asmps)
        asmp->meth = &ssl_connection;
    else
        asmp->meth = &tcp_connection;

    return t;
}

static netsnmp_transport *
_asmp_create_tstring(const char *str, int local,
                     const char *default_target)
{
    return _create_tstring(netsnmp_asmpASMPDomain,
                           sizeof(netsnmp_asmpASMPDomain)/sizeof(oid), 0,
                           str, local, default_target);
}

static netsnmp_transport *
_asmps_create_tstring(const char *str, int local,
                      const char *default_target)
{
    return _create_tstring(netsnmp_asmpASMPSDomain,
                           sizeof(netsnmp_asmpASMPSDomain)/sizeof(oid), 1,
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
