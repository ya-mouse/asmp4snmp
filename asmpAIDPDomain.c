#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "asmp.h"

#include <net-snmp/types.h>
#include <net-snmp/output_api.h>

#include <net-snmp/library/snmp_transport.h>

typedef struct netsnmp_udp_addr_pair_s {
    struct sockaddr_in remote_addr;
    struct in_addr local_addr;
} netsnmp_udp_addr_pair;

int netsnmp_sockaddr_in2();

oid netsnmp_asmpAIDPDomain[] = { TRANSPORT_DOMAIN_AIDP };
static netsnmp_tdomain asmpDomain;

netsnmp_transport *netsnmp_udp_create_tstring();
netsnmp_transport *netsnmp_udp_create_ostring();

/*
 * Return a string representing the address in data, or else the "far end"
 * address if data is NULL.  
 */

static char *
_udp_fmtaddr(netsnmp_transport *t, void *data, int len)
{
    netsnmp_udp_addr_pair *addr_pair = NULL;

    if (t != NULL && t->data != NULL) {
        addr_pair = (netsnmp_udp_addr_pair *) ((struct asmp_connection *)t->data)->addr_pair;
    }

    if (addr_pair == NULL) {
        return strdup("UDP: unknown");
    } else {
        struct sockaddr_in *to = NULL;
	char tmp[64];
        to = (struct sockaddr_in *) &(addr_pair->remote_addr);
        if (to == NULL) {
            return strdup("UDP: unknown");
        }

        sprintf(tmp, "UDP: [%s]:%hu",
                inet_ntoa(to->sin_addr), ntohs(to->sin_port));
        return strdup(tmp);
    }
}

static void
_udp_sockopt_set(int fd, int local)
{
    /*
     * Allow the same port to be specified multiple times without failing.
     *    (useful for a listener)
     */
    {
        int             one = 1;
        DEBUGMSGTL(("socket:option", "setting socket option SO_REUSEADDR\n"));
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *) &one,
                   sizeof(one));
    }

    /*
     * Try to set the send and receive buffers to a reasonably large value, so
     * that we can send and receive big PDUs (defaults to 8192 bytes (!) on
     * Solaris, for instance).  Don't worry too much about errors -- just
     * plough on regardless.  
     */
    netsnmp_sock_buffer_set(fd, SO_SNDBUF, local, 0);
    netsnmp_sock_buffer_set(fd, SO_RCVBUF, local, 0);
}

# define _dstaddr(x) (&(((struct in_pktinfo *)(CMSG_DATA(x)))->ipi_addr))

static int _udp_recvfrom(int s, void *buf, int len, struct sockaddr *from, socklen_t *fromlen, struct in_addr *dstip)
{
    int r;
    struct iovec iov[1];
    char cmsg[CMSG_SPACE(sizeof(struct in_pktinfo))];
    struct cmsghdr *cmsgptr;
    struct msghdr msg;

    iov[0].iov_base = buf;
    iov[0].iov_len = len;

    memset(&msg, 0, sizeof msg);
    msg.msg_name = from;
    msg.msg_namelen = *fromlen;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &cmsg;
    msg.msg_controllen = sizeof(cmsg);

    r = recvmsg(s, &msg, 0);

    if (r == -1) {
        return -1;
    }
    
    DEBUGMSGTL(("netsnmp_udp", "got source addr: %s\n", inet_ntoa(((struct sockaddr_in *)from)->sin_addr)));
    for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL; cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
        if (cmsgptr->cmsg_level == SOL_IP && cmsgptr->cmsg_type == IP_PKTINFO) {
            memcpy((void *) dstip, _dstaddr(cmsgptr), sizeof(struct in_addr));
            DEBUGMSGTL(("netsnmp_udp", "got destination (local) addr %s\n",
                    inet_ntoa(*dstip)));
        }
    }
    return r;
}

static int _udp_sendto(int fd, struct in_addr *srcip, struct sockaddr *remote,
			void *data, int len)
{
    struct iovec iov = { data, len };
    struct {
        struct cmsghdr cm;
        struct in_pktinfo ipi;
    } cmsg;
    struct msghdr m;

    cmsg.cm.cmsg_len = sizeof(struct cmsghdr) + sizeof(struct in_pktinfo);
    cmsg.cm.cmsg_level = SOL_IP;
    cmsg.cm.cmsg_type = IP_PKTINFO;
    cmsg.ipi.ipi_ifindex = 0;
    cmsg.ipi.ipi_spec_dst.s_addr = (srcip ? srcip->s_addr : INADDR_ANY);

    m.msg_name		= remote;
    m.msg_namelen	= sizeof(struct sockaddr_in);
    m.msg_iov		= &iov;
    m.msg_iovlen	= 1;
    m.msg_control	= &cmsg;
    m.msg_controllen	= sizeof(cmsg);
    m.msg_flags		= 0;

    return sendmsg(fd, &m, MSG_NOSIGNAL|MSG_DONTWAIT);
}

static int
_udp_recv(netsnmp_transport *t, void *buf, int size,
		 void **opaque, int *olength)
{
    int             rc = -1;
    socklen_t       fromlen = sizeof(struct sockaddr);
    netsnmp_udp_addr_pair *addr_pair = NULL;
    struct sockaddr *from;

    if (t != NULL && t->sock >= 0) {
        addr_pair = (netsnmp_udp_addr_pair *) malloc(sizeof(netsnmp_udp_addr_pair));
        if (addr_pair == NULL) {
            *opaque = NULL;
            *olength = 0;
            return -1;
        } else {
            memset(addr_pair, 0, sizeof(netsnmp_udp_addr_pair));
            from = (struct sockaddr *) &(addr_pair->remote_addr);
        }

	while (rc < 0) {
#if 1 //defined(linux) && defined(IP_PKTINFO)
            rc = _udp_recvfrom(t->sock, buf, size, from, &fromlen, &(addr_pair->local_addr));
#else
            rc = recvfrom(t->sock, buf, size, 0, from, &fromlen);
#endif /* linux && IP_PKTINFO */
	    if (rc < 0 && errno != EINTR) {
		break;
	    }
	}

        if (rc >= 0) {
            char *str = _udp_fmtaddr(NULL, addr_pair, sizeof(netsnmp_udp_addr_pair));
            DEBUGMSGTL(("netsnmp_udp",
			"recvfrom fd %d got %d bytes (from %s)\n",
			t->sock, rc, str));
            free(str);
        } else {
            DEBUGMSGTL(("netsnmp_udp", "recvfrom fd %d err %d (\"%s\")\n",
                        t->sock, errno, strerror(errno)));
        }
        *opaque = (void *)addr_pair;
        *olength = sizeof(netsnmp_udp_addr_pair);
    }
    return rc;
}



static int
_udp_send(netsnmp_transport *t, void *buf, int size,
		 void **opaque, int *olength)
{
    int rc = -1;
    netsnmp_udp_addr_pair *addr_pair = NULL;
    struct sockaddr *to = NULL;

    if (t != NULL && t->data != NULL &&
                t->data_length == sizeof(struct asmp_connection)) {
        addr_pair = (netsnmp_udp_addr_pair *) ((struct asmp_connection *)t->data)->addr_pair;
    }

    to = (struct sockaddr *) &(addr_pair->remote_addr);

    if (to != NULL && t != NULL && t->sock >= 0) {
        char *str = _udp_fmtaddr(NULL, (void *) addr_pair,
                                        sizeof(netsnmp_udp_addr_pair));
        DEBUGMSGTL(("netsnmp_udp", "send %d bytes from %p to %s on fd %d\n",
                    size, buf, str, t->sock));
        free(str);
	while (rc < 0) {
#if 1 // defined(linux) && defined(IP_PKTINFO)
            rc = _udp_sendto(t->sock, addr_pair ? &(addr_pair->local_addr) : NULL, to, buf, size);
#else
            rc = sendto(t->sock, buf, size, 0, to, sizeof(struct sockaddr));
#endif /* linux && IP_PKTINFO */
	    if (rc < 0 && errno != EINTR) {
                DEBUGMSGTL(("netsnmp_udp", "sendto error, rc %d (errno %d)\n",
                            rc, errno));
		break;
	    }
	}
    }
    return rc;
}

static int
_udp_close(netsnmp_transport *t)
{
    int rc = -1;
    if (t->sock >= 0) {
#ifndef HAVE_CLOSESOCKET
        rc = close(t->sock);
#else
        rc = closesocket(t->sock);
#endif
        t->sock = -1;
    }
    return rc;
}

static netsnmp_transport *
_udp_create_tstring(const char *str, int local,
			   const char *default_target)
{
    struct sockaddr_in addr;
    netsnmp_transport *t = NULL;
    struct asmp_connection *asmp;
    int             rc = 0;
    char           *client_socket = NULL;

    if (!netsnmp_sockaddr_in2(&addr, str, default_target))
        return NULL;

    if (addr.sin_family != AF_INET)
        return NULL;

    t = (netsnmp_transport *) malloc(sizeof(netsnmp_transport));
    if (t == NULL)
        return NULL;

    memset(t, 0, sizeof(netsnmp_transport));

    t->domain = netsnmp_asmpAIDPDomain;
    t->domain_length = sizeof(netsnmp_asmpAIDPDomain)/sizeof(oid);

    t->sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (t->sock < 0)
        goto free;

    _udp_sockopt_set(t->sock, local);

    asmp = calloc(1, sizeof(struct asmp_connection));
    t->data = asmp;
    t->data_length = sizeof(struct asmp_connection);

    if (local) {
        /*
         * This session is inteneded as a server, so we must bind on to the
         * given IP address, which may include an interface address, or could
         * be INADDR_ANY, but certainly includes a port number.
         */

        t->local = (u_char *) malloc(6);
        if (t->local == NULL)
            goto exit;
        memcpy(t->local, (u_char *) & (addr.sin_addr.s_addr), 4);
        t->local[4] = (htons(addr.sin_port) & 0xff00) >> 8;
        t->local[5] = (htons(addr.sin_port) & 0x00ff) >> 0;
        t->local_length = 6;

#if defined(linux) && defined(IP_PKTINFO)
        { 
            int sockopt = 1;
            if (setsockopt(t->sock, SOL_IP, IP_PKTINFO, &sockopt, sizeof sockopt) == -1) {
                DEBUGMSGTL(("netsnmp_udp", "couldn't set IP_PKTINFO: %s\n",
                    strerror(errno)));
                return NULL;
            }
            DEBUGMSGTL(("netsnmp_udp", "set IP_PKTINFO\n"));
        }
#endif
        rc = bind(t->sock, (struct sockaddr *) &addr,
                  sizeof(struct sockaddr));
        if (rc != 0)
            goto exit;
    } else {
        /*
         * This is a client session.  If we've been given a
         * client address to send from, then bind to that.
         * Otherwise the send will use "something sensible".
         */
        client_socket = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                                              NETSNMP_DS_LIB_CLIENT_ADDR);
        if (client_socket) {
            struct sockaddr_in client_addr;
            netsnmp_sockaddr_in2(&client_addr, client_socket, NULL);
            client_addr.sin_port = 0;
            bind(t->sock, (struct sockaddr *)&client_addr,
                  sizeof(struct sockaddr));
        }
        /*
         * Save the (remote) address in the
         * transport-specific data pointer for later use by netsnmp_udp_send.
         */

        asmp->addr_pair = malloc(sizeof(netsnmp_udp_addr_pair));

        memset(asmp->addr_pair, 0, sizeof(netsnmp_udp_addr_pair));
        memcpy(&((netsnmp_udp_addr_pair *)asmp->addr_pair)->remote_addr, &addr, sizeof(struct sockaddr_in));

        t->remote = (u_char *)malloc(6);
        if (t->remote == NULL)
            goto exit;
        memcpy(t->remote, (u_char *) & (addr.sin_addr.s_addr), 4);
        t->remote[4] = (htons(addr.sin_port) & 0xff00) >> 8;
        t->remote[5] = (htons(addr.sin_port) & 0x00ff) >> 0;
        t->remote_length = 6;
    }

    /*
     * 16-bit length field, 8 byte UDP header, 20 byte IPv4 header  
     */

    t->msgMaxSize = 0xffff - 8 - 20;
    t->f_recv     = _udp_recv;
    t->f_send     = _udp_send;
    t->f_close    = _udp_close;
    t->f_accept   = NULL;
    t->f_fmtaddr  = _udp_fmtaddr;

    asmp->proto = ASMP_PROTO_AIDP;

    goto exit;

free:
    if (t->sock >= 0)
        _udp_close(t);
    netsnmp_transport_free(t);
    t = NULL;

exit:

    return t;
}


static netsnmp_transport *
_udp_create_ostring(const u_char * o, size_t o_len, int local)
{
    return NULL;
}


void
netsnmp_aidp_ctor(void)
{
    asmpDomain.name = netsnmp_asmpAIDPDomain;
    asmpDomain.name_length = sizeof(netsnmp_asmpAIDPDomain) / sizeof(oid);
    asmpDomain.prefix = (const char **)calloc(2, sizeof(char *));
    asmpDomain.prefix[0] = "aidp";

    asmpDomain.f_create_from_tstring_new = _udp_create_tstring;
    asmpDomain.f_create_from_ostring = _udp_create_ostring;

    netsnmp_tdomain_register(&asmpDomain);
}
