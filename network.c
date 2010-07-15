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

static struct asmp_net_meth tcp_connection = {
    .write = _tcp_write,
    .read  = _tcp_read
};

static struct asmp_net_meth ssl_connection = {
    .write = _ssl_write,
    .read  = _ssl_read
};

int
asmp_net_connect(struct asmp_cfg *cfg, const char *host, int port)
{
    //int status;
    unsigned char ip[4]; 
    unsigned long addr;
    struct sockaddr_in them;
    uint8_t req[] = {ASMP_SESSION_SETUP_REQUEST_FIELD_CONN_TYPE, 0, 2, 0,
                     cfg->is_ssl ? ASMP_SESSION_SETUP_SSL_CONNECTION : ASMP_SESSION_SETUP_TCP_CONNECTION,
                     ASMP_FIELD_TERM};

    memset(ip, 0, sizeof(ip));
    printf("Host: [%s]\n", host);
    BIO_get_host_ip(host, &(ip[0]));
    addr = (unsigned long)
            ((unsigned long)ip[0]<<24L)|
            ((unsigned long)ip[1]<<16L)|
            ((unsigned long)ip[2]<< 8L)|
            ((unsigned long)ip[3]);

    memset(&them, 0, sizeof(them));
    them.sin_family = AF_INET;
    them.sin_port   = htons((unsigned short)port);
    them.sin_addr.s_addr = htonl(addr);

    cfg->tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(cfg->tcp_sock, (struct sockaddr *)&them, sizeof(them)) < 0)
        return -1;

    cfg->meth = &tcp_connection;

    if (asmp_request(cfg, ASMP_SESSION_SETUP_REQUEST, sizeof(req), req) != ASMP_SOH) {
        close(cfg->tcp_sock);
        return -2;
    }

    printf("Connection established\n");
    if (cfg->is_ssl) {
        // Establish SSL connection
        cfg->meth = &ssl_connection;
    }

    //asmp_net_version(&cfg);
    //status = asmp_net_login(&cfg, NULL, NULL);

    return 0;
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

#if 0
int
aten_net_login(struct aten_cfg *cfg,
               const char *url,
               const char *user,
               const char *passwd)
{
    char    *p;
    char    *host    = NULL;
    char    *sid     = NULL;
    char    *target  = NULL;
    char    *cookie  = NULL;
    char     ref[64];
    char    *data    = NULL;
    int      i;
    int      rc      = -2;
    SSL     *con     = NULL;
    SSL_CTX *ctx     = NULL;

    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
        fprintf(stderr, "aten_net_login: Couldn't create SSL context\n");
        goto end2;
    }
    SSL_CTX_set_default_verify_paths(ctx);

    /* SSL_VERIFY_NONE instructs OpenSSL not to abort SSL_connect if the
       certificate is invalid.  We verify the certificate separately in
       ssl_check_certificate, which provides much better diagnostics
       than examining the error stack after a failed SSL_connect.  */
    SSL_CTX_set_verify (ctx, SSL_VERIFY_NONE, NULL);

    /* Since fd_write unconditionally assumes partial writes (and
       handles them correctly), allow them in OpenSSL.  */
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

    /* The OpenSSL library can handle renegotiations automatically, so
       tell it to do so.  */
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    host = strdup(url);
    p    = strchr(host, '/');
    if (p != NULL)
        *p = '\0';
    strncpy(ref, p == NULL ? "kvm.html" : p+1, sizeof(ref));

    /* Make 4 iterations to login */
    for (i=0; i<4; i++) {
        char  buf[512];
        char  hdr[512];
        char *plen;
        long  len;
        long  rd;
        int   s;
        int   k;

        con = SSL_new(ctx);
        if (con == NULL) {
            fprintf(stderr, "aten_net_login: Coulnd't create SSL\n");
            goto end;
        }
        s = aten_net_connect(host, 443);
        SSL_set_fd(con, s);
        SSL_set_connect_state(con);

        if (SSL_connect(con) <= 0 || con->state != SSL_ST_OK) {
            fprintf(
                stderr,
                "aten_net_login: Coulnd't establish SSL connection with `%s' host\n",
                host);
            goto end;
        }

        /* Aten doesn't care of path */
        if (i == 0) {
            snprintf(buf, sizeof(buf),
                "GET /%s HTTP/1.1\r\nHost: %s\r\nReferer: http://%s/%s\r\n\r\n",
                ref, host, host, ref);
            p = strdup(ref);
            snprintf(ref, sizeof(ref), "https://%s/%s", host, p);
            free(p);
        } else if (i == 1) {
            snprintf(buf, sizeof(buf),
                "GET /%s HTTP/1.1\r\nHost: %s\r\nReferer: %s\r\n\r\n",
                sid, host, ref);
            snprintf(ref, sizeof(ref), "https://%s/%s", host, sid);
        } else if (i == 2) {
            char *puser;
            char *ppasswd;
            char *phost;

            puser   = _convert(user);
            ppasswd = _convert(passwd);
            phost   = _convert(host);
            snprintf(buf, sizeof(buf),
                "POST /KVMIP HTTP/1.1\r\nHost: %s\r\n"
                "Referer: %s\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: %d\r\n\r\n"
                "KVMIP_GMTIME=%lu&KVMIP_LOGIN=%s+%s+%s+%s&KVMIP_TARGETID=%s\r\n\r\n",
                host,
                ref,
                13+10+13+strlen(puser)+1+strlen(ppasswd)+1+strlen(phost)+1+strlen(target)+16+strlen(target),
                time(NULL),
                puser, ppasswd, phost, target,
                target);
            free(puser);
            free(ppasswd);
            free(phost);
            snprintf(ref, sizeof(ref), "https://%s/KVMIP", host);
        } else if (i == 3) {
            snprintf(buf, sizeof(buf),
                "GET /%s/CN6000main.jar HTTP/1.1\r\nHost: %s\r\n"
                "Referer: %s\r\n"
                "Cookie: %s\r\n\r\n",
                sid, host,
                ref,
                cookie);
        }

        SSL_write(con, buf, strlen(buf));
        /* Receive headers */
        len = SSL_read(con, hdr, sizeof(hdr)-1);
        hdr[len-1] = '\0';
        plen = strstr(hdr, "Content-Length: ");
        if (plen == 0) {
            fprintf(stderr, "aten_net_login: Malformed HTTP header\n");
            goto end;
        }
        plen = strchr(plen, ' ')+1;
        k = strchr(plen, '\r')-plen;
        plen[k] = '\0';
        len = atol(plen);
        plen[k] = '\r';
        data = calloc(1, len+1);
        /* Receive data */
        rd = len;
        while (rd > 0)
            rd -= SSL_read(con, data+len-rd, len);

        if (i == 0) {
            sid = strstr(data, "hostname + \"/");
            if (sid == NULL) {
                fprintf(stderr, "aten_net_login: Couldn't find SID\n");
                goto end;
            }
            sid = strchr(sid, '/')+1;
            sid[24] = '\0';
            sid = strdup(sid);
        } else if (i == 1) {
            target = strstr(data, "KVMIP_TARGETID\" value=");
            /* Something goes wrong */
            if (target == NULL) {
                fprintf(stderr, "aten_net_login: Couldn't find TARGET\n");
                goto end;
            }
            target = strchr(target, '=')+2;
            target[8] = '\0';
            target = strdup(target);
        } else if (i == 2) {
            free(sid);
            free(target);
            sid    = NULL;
            target = NULL;
            cookie = strstr(hdr, "Set-Cookie: ");
            sid    = strstr(data, "name=\"KVMIP_SID\"");
            target = strstr(data, "name=\"KVMIP_TARGET\"");
            if (cookie == NULL) {
                fprintf(stderr, "aten_net_login: Couldn't find Cookie\n");
                goto end2;
            }
            if (sid == NULL) {
                fprintf(stderr, "aten_net_login: Couldn't find SID\n");
                goto end2;
            }
            if (target == NULL) {
                fprintf(stderr, "aten_net_login: Couldn't find TARGET\n");
                goto end2;
            }
            cookie = strchr(cookie, ' ')+1;
            sid    = strchr(sid    + sizeof("name="), '=')+2;
            target = strchr(target + sizeof("name="), '=')+2;
            cookie[strchr(cookie, '\r')-cookie] = '\0';
            sid[strchr(sid, '"')-sid]           = '\0';
            target[strchr(target, '"')-target]  = '\0';
            cookie = strdup(cookie);
            sid    = strdup(sid);
            target = strdup(target);
        } else if (i == 3) {
            struct archive       *a;
            struct archive_entry *ae;

            a = archive_read_new();
            archive_read_support_format_zip(a);
            archive_read_open_memory(a, data, len);
            while (!archive_read_next_header(a, &ae)) {
                if (!strcmp(archive_entry_pathname(ae), "JCSMain.class")) {
                    /* Let's handle different version of JCSMain class */
                    char *s2[] = {"l0885616841", "l1207243178", NULL};
                    char **s = s2;
                    int  idx[][2] = {{250,254}, {250,254}};
                    int  size   = archive_entry_size(ae);
                    p = malloc(size);
                    archive_read_data(a, p, size);
                    while (*s != NULL) {
                        char *jp = aten_java_get_string((uint8_t *)p, *s);
                        if (jp != NULL) {
                            rc = _decode_cfg_string(cfg, jp);
                            free(jp);
                            cfg->key_sae_idx = idx[(s-s2)/sizeof(char*)][0];
                            cfg->key_siv_idx = idx[(s-s2)/sizeof(char*)][1];
                            printf("%d,%d\n",
                               cfg->key_sae_idx,
                               cfg->key_siv_idx);
                            break;
                        }
                        s++;
                    }
                    free(p);
                    break;
                }
            }
            archive_read_close(a);
            archive_read_finish(a);
        }

        SSL_shutdown(con);
        SSL_set_connect_state(con);
        SSL_free(con);
        close(s);
        free(data);
        data = NULL;
        con  = NULL;
    }

end:
    if (target != NULL)
        free(target);
    if (sid != NULL)
        free(sid);
    if (cookie != NULL)
        free(cookie);

end2:
    if (host != NULL)
        free(host);
    if (data != NULL)
        free(data);

    if (ctx != NULL)
        SSL_CTX_free(ctx);
    if (con != NULL)
        SSL_free(con);

    return rc;
}
#endif
