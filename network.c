#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/ssl.h>

#include "network.h"
#include "session.h"

static int _tcp_write();
static int _tcp_read();
static int _ssl_write();
static int _ssl_read();
static int _dsr_asmp_version();
static int _setup_ssl();

static struct asmp_net_meth tcp_connection = {
    .write = _tcp_write,
    .read  = _tcp_read
};

static struct asmp_net_meth ssl_connection = {
    .write = _ssl_write,
    .read  = _ssl_read
};

int
asmp_net_connect(struct asmp_cfg *cfg)
{
    int status;
    unsigned char ip[4]; 
    unsigned long addr;
    struct sockaddr_in them;

    struct asmp_pdu *pdu;
    struct asmp_pdu *response = NULL;
    uint8_t req[] = {ASMP_SOH, 0, 2,
                     0, cfg->is_ssl ? ASMP_SESSION_SETUP_SSL_CONNECTION : ASMP_SESSION_SETUP_TCP_CONNECTION,
                     ASMP_FIELD_TERM};

    memset(ip, 0, sizeof(ip));
    BIO_get_host_ip(cfg->host, &(ip[0]));
    addr = (unsigned long)
            ((unsigned long)ip[0]<<24L)|
            ((unsigned long)ip[1]<<16L)|
            ((unsigned long)ip[2]<< 8L)|
            ((unsigned long)ip[3]);

    memset(&them, 0, sizeof(them));
    them.sin_family = AF_INET;
    them.sin_port   = htons(cfg->port);
    them.sin_addr.s_addr = htonl(addr);

    cfg->tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(cfg->tcp_sock, (struct sockaddr *)&them, sizeof(them)) < 0)
        return -1;

    cfg->meth = &tcp_connection;

    pdu = asmp_pdu_new(ASMP_SESSION_SETUP_REQUEST, req, sizeof(req));
    if (asmp_request(cfg, pdu, &response) != 0 || response == NULL) {
        asmp_pdu_free(pdu);
        close(cfg->tcp_sock);
        return -2;
    }
    asmp_pdu_free(response);
    asmp_pdu_free(pdu);

    if (cfg->is_ssl)
        status = _setup_ssl(cfg);

    status = _dsr_asmp_version(cfg);
    status = asmp_net_login(cfg, NULL, NULL);

    return status;
}

int
asmp_net_login(struct asmp_cfg *cfg, const char *user, const char *passwd)
{
    int rc;
    int u_len;
    int p_len;
    struct asmp_pdu *pdu;
    struct asmp_pdu *response = NULL;
    uint8_t *req;

    u_len =   user == NULL ? 0 : strlen(user);
    p_len = passwd == NULL ? 0 : strlen(passwd);

    req = malloc(1+3+2+1+u_len+p_len);
    req[0] = ASMP_SOH;
    req[1] = (u_len >> 8) & 0xff;
    req[2] =  u_len & 0xff;
    if (u_len != 0)
        memcpy(req+2,       user,   u_len);
    req[3+u_len] = 2;
    req[4+u_len] = (p_len >> 8) & 0xff;
    req[5+u_len] =  p_len & 0xff;
    if (p_len != 0)
        memcpy(req+6+u_len, passwd, p_len);
    req[6+u_len+p_len] = ASMP_FIELD_TERM;

    pdu = asmp_pdu_new(ASMP_LOGIN_REQUEST, req, 7+u_len+p_len);
    if (asmp_request(cfg, pdu, &response) != 0 || response == NULL) {
        rc = -1;
        goto free;
    }

    asmp_pdu_free(response);
    rc = 0;

free:
    asmp_pdu_free(pdu);
    free(req);

    return rc;
}

int
asmp_net_logout(struct asmp_cfg *cfg)
{
    int rc;
    struct asmp_pdu *pdu;
    struct asmp_pdu *response = NULL;
    uint8_t req[] = {ASMP_FIELD_TERM};

    pdu = asmp_pdu_new(ASMP_LOGOUT_REQUEST, req, sizeof(req));
    if (asmp_request(cfg, pdu, &response) != 0 || response == NULL) {
        rc = -1;
        goto free;
    }

    asmp_pdu_free(response);
    rc = 0;

free:
    asmp_pdu_free(pdu);
    return rc;
}

int
asmp_select_fd (int fd, double maxtime, int wait_for)
{
  fd_set fdset;
  fd_set *rd = NULL, *wr = NULL;
  struct timeval tmout;
  int result;

  FD_ZERO (&fdset);
  FD_SET (fd, &fdset);
  if (wait_for & 2)
    rd = &fdset;
  if (wait_for & 4)
    wr = &fdset;

  tmout.tv_sec = (long) maxtime;
  tmout.tv_usec = 1000000 * (maxtime - (long) maxtime);

  do
    result = select (fd + 1, rd, wr, NULL, &tmout);
  while (result < 0 && errno == EINTR);

  return result;
}

struct asmp_pdu *
asmp_pdu_new(uint8_t cmd, const void *buf, int len)
{
    struct asmp_pdu *pdu;

    pdu = malloc(sizeof(struct asmp_pdu));
    pdu->seq  = 0;
    pdu->cmd  = cmd;
    pdu->len  = len;
    pdu->data = malloc(len);
    memcpy(pdu->data, buf, len);

    return pdu;
}

void
asmp_pdu_free(struct asmp_pdu *pdu)
{
    if (pdu == NULL)
        return;
    if (pdu->data != NULL)
        free(pdu->data);
    free(pdu);
}

int
asmp_request(struct asmp_cfg *cfg, const struct asmp_pdu *pdu, struct asmp_pdu **response)
{
    int              rc;
    uint8_t         *buf;
    uint32_t         sz;
    struct asmp_pdu *resp;

    if (cfg->meth == NULL)
        return -1;

    cfg->seq++;
    sz  = htonl(pdu->len);
    buf = calloc(1, 13+pdu->len);
    buf[0]  = ASMP_SOH;
    memcpy(buf+1, "ASMP", 4);
    buf[5]  = (cfg->seq >> 8) & 0xff;
    buf[6]  =  cfg->seq & 0xff;
    buf[7]  = pdu->cmd;
    memcpy(buf+8, &sz, 4);
    memcpy(buf+12, pdu->data, pdu->len);
    buf[12+pdu->len] = ASMP_TERMINATOR;

    xdump(buf, pdu->len+13, ">> ");

    cfg->meth->write(cfg, buf, 13+pdu->len);

    cfg->meth->read(cfg, buf, 1);
    if (*buf != ASMP_SOH) {
        fprintf(stderr, "Wrong response: [%02x]\n", *buf);
        rc = -1;
        goto free;
    }
    cfg->meth->read(cfg, buf, 4);
    if (strncmp((char *)buf, "ASMP", 4)) {
        fprintf(stderr, "Wrong response: [%02x]\n", *buf);
        rc = -1;
        goto free;
    }

    resp = malloc(sizeof(struct asmp_pdu));
    cfg->meth->read(cfg, &resp->seq, 2);
    cfg->meth->read(cfg, &resp->cmd, 1);
    cfg->meth->read(cfg, &resp->len, 4);
    resp->seq = ntohs(resp->seq);
    resp->len = ntohl(resp->len);
    DEBUGMSGTL(("asmp", "[%02x][%02x][%04x]\n", resp->seq, resp->cmd, resp->len));
    if (resp->len > 0x40000) {
        fprintf(stderr, "ASMP LENGTH TOO BIG (%08x)\n", resp->len);
        rc = -2;
        goto free_resp;
    }
    resp->data = malloc(resp->len);
    cfg->meth->read(cfg, resp->data, resp->len);
    cfg->meth->read(cfg, buf, 1);
    if (*buf != ASMP_TERMINATOR) {
        fprintf(stderr, "Invalid terminator (%x)\n", *buf);
        rc = -2;
        goto free_resp;
    }

    xdump(resp->data, resp->len, "<< ");

    *response = resp;
    rc = 0;
    goto free;

free_resp:
    free(resp);

free:
    free(buf);
    return rc;
}


static int
_dsr_asmp_version(struct asmp_cfg *cfg)
{
    int rc;
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

    return rc;
}

static int
_setup_ssl(struct asmp_cfg *cfg)
{
    int rc = -1;

    cfg->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (cfg->ssl_ctx == NULL) {
        fprintf(stderr, "asmp_net_connect: Couldn't create SSL context\n");
        goto exit;
    }
    SSL_CTX_set_default_verify_paths(cfg->ssl_ctx);

    /* SSL_VERIFY_NONE instructs OpenSSL not to abort SSL_connect if the
       certificate is invalid.  We verify the certificate separately in
       ssl_check_certificate, which provides much better diagnostics
       than examining the error stack after a failed SSL_connect.  */
    SSL_CTX_set_verify (cfg->ssl_ctx, SSL_VERIFY_NONE, NULL);

    /* Since fd_write unconditionally assumes partial writes (and
       handles them correctly), allow them in OpenSSL.  */
    SSL_CTX_set_mode(cfg->ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

    /* The OpenSSL library can handle renegotiations automatically, so
       tell it to do so.  */
    SSL_CTX_set_mode(cfg->ssl_ctx, SSL_MODE_AUTO_RETRY);

    cfg->ssl_sock = SSL_new(cfg->ssl_ctx);
    if (cfg->ssl_sock == NULL) {
        fprintf(stderr, "asmp_net_connect: Coulnd't create SSL\n");
        goto exit;
    }

    SSL_set_fd(cfg->ssl_sock, cfg->tcp_sock);
    SSL_set_connect_state(cfg->ssl_sock);

    if (SSL_connect(cfg->ssl_sock) <= 0 || cfg->ssl_sock->state != SSL_ST_OK) {
        fprintf(stderr,
                "asmp_net_connect: Coulnd't establish SSL connection with `%s' host\n",
                cfg->host);
            goto exit;
    }

    cfg->meth = &ssl_connection;
    rc = 0;

exit:
    return rc;
}

static int
_tcp_write(struct asmp_cfg *cfg, const void *buf, int num)
{
    return write(cfg->tcp_sock, buf, num);
}

static int
_tcp_read(struct asmp_cfg *cfg, void *buf, int num)
{
    return read(cfg->tcp_sock, buf, num);
}

static int
_ssl_write(struct asmp_cfg *cfg, const void *buf, int num)
{
    return SSL_write(cfg->ssl_sock, buf, num);
}

static int
_ssl_read(struct asmp_cfg *cfg, void *buf, int num)
{
   return SSL_read(cfg->ssl_sock, buf, num);
}
