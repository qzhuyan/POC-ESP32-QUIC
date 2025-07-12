/*
 * ngtcp2
 *
 * Copyright (c) 2021 ngtcp2 contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_wolfssl.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

//#include <ev.h>
#include "esp_ev_compat.h"
#include "ngtcp2_sample.h"
#include <esp_task_wdt.h>
#include "mqtt_quic_transport.h"  // This includes esp_timer.h

#include "esp_log.h"
static const char *TAG = "QUIC";
// @NOTE: hack to avoid using stderr
#undef stderr
#define stderr stdout
/*
#define REMOTE_HOST "127.0.0.1"
#define REMOTE_PORT "4433"
#define ALPN "\xahq-interop"
#define MESSAGE "GET /\r\n"
*/

/*
 * Example 1: Handshake with www.google.com
 *
 * #define REMOTE_HOST "www.google.com"
 * #define REMOTE_PORT "443"
 * #define ALPN "\x2h3"
 *
 * and undefine MESSAGE macro.
 */

#define REMOTE_HOST "127.0.0.1"
#define REMOTE_PORT "14567"
#define ALPN "\x4mqtt"
struct client g_client;  // Make the client struct global

// Global configuration for dynamic hostname/port
static quic_client_config_t g_config = {
    .hostname = REMOTE_HOST,
    .port = REMOTE_PORT,
    .alpn = ALPN
};

// Global state for QUIC connection
static volatile bool g_quic_connected = false;
static volatile bool g_quic_handshake_completed = false;
static volatile uint64_t g_quic_n_local_streams = 0;

// Mutex for thread-safe QUIC operations
SemaphoreHandle_t quic_mutex = NULL;
static bool quic_processing = false;  // Flag to prevent reentrancy

#define APP_BUFFER_SIZE 4096
static uint8_t app_recv_buffer[APP_BUFFER_SIZE];
static size_t app_recv_buffer_len = 0;
static size_t app_recv_buffer_read_pos = 0;

static uint64_t timestamp(void) {
  return esp_timer_get_time() * 1000;
}

static int create_sock(struct sockaddr *addr, socklen_t *paddrlen,
                       const char *host, const char *port) {
  struct addrinfo hints = {0};
  struct addrinfo *res, *rp;
  int rv;
  int fd = -1;

  hints.ai_flags = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  rv = getaddrinfo(host, port, &hints, &res);
  if (rv != 0) {
    // Replace gai_strerror with displaying the error code directly
    ESP_LOGE(TAG, "getaddrinfo failed with error code: %d", rv);
    return -1;
  }

  for (rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd == -1) {
      continue;
    }

    break;
  }

  if (fd == -1) {
    goto end;
  }

  *paddrlen = rp->ai_addrlen;
  memcpy(addr, rp->ai_addr, rp->ai_addrlen);

end:
  freeaddrinfo(res);

  return fd;
}

static int connect_sock(struct sockaddr *local_addr, socklen_t *plocal_addrlen,
                        int fd, const struct sockaddr *remote_addr,
                        size_t remote_addrlen) {
  socklen_t len;

  if (connect(fd, remote_addr, (socklen_t)remote_addrlen) != 0) {
    ESP_LOGE(TAG, "connect: %s", strerror(errno));
    return -1;
  }

  len = *plocal_addrlen;

  if (getsockname(fd, local_addr, &len) == -1) {
    ESP_LOGE(TAG, "getsockname: %s", strerror(errno));
    return -1;
  }

  *plocal_addrlen = len;

  return 0;
}

struct client {
  ngtcp2_crypto_conn_ref conn_ref;
  int fd;
  struct sockaddr_storage local_addr;
  socklen_t local_addrlen;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  ngtcp2_conn *conn;

  struct {
    int64_t stream_id;
    const uint8_t *data;
    size_t datalen;
    size_t nwrite;
  } stream;

  ngtcp2_ccerr last_error;

  ev_io rev;
  ev_timer timer;
};

static int numeric_host_family(const char *hostname, int family) {
  uint8_t dst[sizeof(struct in6_addr)];
  return inet_pton(family, hostname, dst) == 1;
}

static int numeric_host(const char *hostname) {
  return numeric_host_family(hostname, AF_INET) ||
         numeric_host_family(hostname, AF_INET6);
}

static int client_ssl_init(struct client *c) {
  c->ssl_ctx = SSL_CTX_new(TLS_client_method());
  if (!c->ssl_ctx) {
    ESP_LOGE(TAG, "SSL_CTX_new: %s", ERR_error_string(ERR_get_error(), NULL));
    return -1;
  }

  if (ngtcp2_crypto_wolfssl_configure_client_context(c->ssl_ctx) != 0) {
    ESP_LOGE(TAG, "ngtcp2_crypto_wolfssl_configure_client_context failed");
    return -1;
  }

  wolfSSL_CTX_UseSNI(c->ssl_ctx, WOLFSSL_SNI_HOST_NAME, g_config.hostname, strlen(g_config.hostname) + 1);
  wolfSSL_CTX_set_verify(c->ssl_ctx, WOLFSSL_VERIFY_NONE, NULL);

  c->ssl = SSL_new(c->ssl_ctx);
  if (!c->ssl) {
    ESP_LOGE(TAG, "SSL_new: %s", ERR_error_string(ERR_get_error(), NULL));
    return -1;
  }

  SSL_set_app_data(c->ssl, &c->conn_ref);
  SSL_set_connect_state(c->ssl);
  
  // Set ALPN - need to convert string to proper binary format
  uint8_t alpn_list[16];  // Buffer for ALPN list
  size_t alpn_len = strlen(g_config.alpn);
  if (alpn_len > 0 && alpn_len < 15) {
    alpn_list[0] = (uint8_t)alpn_len;  // Length prefix
    memcpy(&alpn_list[1], g_config.alpn, alpn_len);
    SSL_set_alpn_protos(c->ssl, alpn_list, alpn_len + 1);
    ESP_LOGI(TAG, "Set ALPN: %s (length: %zu)", g_config.alpn, alpn_len);
  } else {
    ESP_LOGE(TAG, "Invalid ALPN length: %zu", alpn_len);
  }
  
  if (!numeric_host(g_config.hostname)) {
    SSL_set_tlsext_host_name(c->ssl, g_config.hostname);
  }

  return 0;
}

static void rand_cb(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx) {
  int rv;
  (void)rand_ctx;

  rv = RAND_bytes(dest, (int)destlen);
  if (rv != 1) {
    assert(0);
    abort();
  }
}

static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                    uint8_t *token, size_t cidlen,
                                    void *user_data) {
  (void)conn;
  (void)user_data;

  if (RAND_bytes(cid->data, (int)cidlen) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  cid->datalen = cidlen;

  if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int handshake_completed_cb(ngtcp2_conn *conn, void *user_data) {
    (void)conn;
    (void)user_data;
    ESP_LOGI(TAG, "QUIC handshake completed callback triggered!");
    g_quic_handshake_completed = true;
    return 0;
}

// Forward declaration for recv_stream_data callback
static int recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                           int64_t stream_id, uint64_t offset,
                           const uint8_t *data, size_t datalen,
                           void *user_data, void *stream_user_data);

static int extend_max_local_streams_bidi(ngtcp2_conn *conn,
                                         uint64_t max_streams,
                                         void *user_data) {
  (void)conn;
  (void)user_data; 
  ESP_LOGI(TAG, "Extending max local streams bidi to %" PRIu64 "\n", max_streams);
  g_quic_connected = true;
  g_quic_n_local_streams = max_streams;
  return 0;
}

static void log_printf(void *user_data, const char *fmt, ...) {
  va_list ap;
  (void)user_data;

  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);

  fprintf(stderr, "\n");
}

static int client_quic_init(struct client *c,
                            const struct sockaddr *remote_addr,
                            socklen_t remote_addrlen,
                            const struct sockaddr *local_addr,
                            socklen_t local_addrlen) {
  ESP_LOGI(TAG, "In client_quic_init");
  ngtcp2_path path = {
    .local =
      {
        .addr = (struct sockaddr *)local_addr,
        .addrlen = local_addrlen,
      },
    .remote =
      {
        .addr = (struct sockaddr *)remote_addr,
        .addrlen = remote_addrlen,
      },
  };
  ngtcp2_callbacks callbacks = {
    .client_initial = ngtcp2_crypto_client_initial_cb,
    .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
    .encrypt = ngtcp2_crypto_encrypt_cb,
    .decrypt = ngtcp2_crypto_decrypt_cb,
    .hp_mask = ngtcp2_crypto_hp_mask_cb,
    .recv_retry = ngtcp2_crypto_recv_retry_cb,
    .recv_stream_data = recv_stream_data,  // Add this callback!
    .handshake_completed = handshake_completed_cb,  // Add handshake completion callback
    .extend_max_local_streams_bidi = extend_max_local_streams_bidi,
    .rand = rand_cb,
    .get_new_connection_id = get_new_connection_id_cb,
    .update_key = ngtcp2_crypto_update_key_cb,
    .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
    .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
  };
  ngtcp2_cid dcid, scid;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  int rv;

  dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
  if (RAND_bytes(dcid.data, (int)dcid.datalen) != 1) {
    ESP_LOGE(TAG, "RAND_bytes failed");
    return -1;
  }

  scid.datalen = 8;
  if (RAND_bytes(scid.data, (int)scid.datalen) != 1) {
    fprintf(stderr, "RAND_bytes failed\n");
    return -1;
  }
  ngtcp2_settings_default(&settings);

  settings.initial_ts = timestamp();
  ESP_LOGI(TAG, "===>  INITIAL TS: %lu", settings.initial_ts);
  settings.log_printf = log_printf;

  ngtcp2_transport_params_default(&params);

  params.initial_max_streams_uni = 3;
  params.initial_max_stream_data_bidi_local = 128 * 1024;
  params.initial_max_data = 1024 * 1024;

  rv =
    ngtcp2_conn_client_new(&c->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
                           &callbacks, &settings, &params, NULL, c);
  if (rv != 0) {
    ESP_LOGE(TAG, "ngtcp2_conn_client_new: %s", ngtcp2_strerror(rv));
    return -1;
  }

  ngtcp2_conn_set_tls_native_handle(c->conn, c->ssl);

  return 0;
}

static int client_read(struct client *c) {
  // @NOTE: adjust the buffer size as needed
  uint8_t buf[16384];
  struct sockaddr_storage addr;
  struct iovec iov = {
    .iov_base = buf,
    .iov_len = sizeof(buf),
  };
  struct msghdr msg = {0};
  ssize_t nread;
  ngtcp2_path path;
  ngtcp2_pkt_info pi = {0};
  int rv;

  msg.msg_name = &addr;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  for (;;) {
    msg.msg_namelen = sizeof(addr);

    nread = recvmsg(c->fd, &msg, MSG_DONTWAIT);

    if (nread == -1) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        ESP_LOGE(TAG, "recvmsg: %s", strerror(errno));
      }

      break;
    }

    path.local.addrlen = c->local_addrlen;
    path.local.addr = (struct sockaddr *)&c->local_addr;
    path.remote.addrlen = msg.msg_namelen;
    path.remote.addr = msg.msg_name;

    rv = ngtcp2_conn_read_pkt(c->conn, &path, &pi, buf, (size_t)nread,
                              timestamp());
    if (rv != 0) {
      ESP_LOGE(TAG, "ngtcp2_conn_read_pkt: %s", ngtcp2_strerror(rv));
      if (!c->last_error.error_code) {
        if (rv == NGTCP2_ERR_CRYPTO) {
          ngtcp2_ccerr_set_tls_alert(
            &c->last_error, ngtcp2_conn_get_tls_alert(c->conn), NULL, 0);
        } else {
          ngtcp2_ccerr_set_liberr(&c->last_error, rv, NULL, 0);
        }
      }
      return -1;
    }
  }

  return 0;
}

static int client_send_packet(struct client *c, const uint8_t *data,
                              size_t datalen) {
  struct iovec iov = {
    .iov_base = (uint8_t *)data,
    .iov_len = datalen,
  };
  struct msghdr msg = {0};
  ssize_t nwrite;

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  do {
    nwrite = sendmsg(c->fd, &msg, 0);
  } while (nwrite == -1 && errno == EINTR);

  if (nwrite == -1) {
    ESP_LOGE(TAG, "sendmsg: %s", strerror(errno));
    return -1;
  }

  return 0;
}

static size_t client_get_message(struct client *c, int64_t *pstream_id,
                                 int *pfin, ngtcp2_vec *datav,
                                 size_t datavcnt) {
  if (datavcnt == 0) {
    return 0;
  }

  if (c->stream.stream_id != -1 && c->stream.nwrite < c->stream.datalen) {
    *pstream_id = c->stream.stream_id;
    *pfin = 1;
    datav->base = (uint8_t *)c->stream.data + c->stream.nwrite;
    datav->len = c->stream.datalen - c->stream.nwrite;
    return 1;
  }

  *pstream_id = -1;
  *pfin = 0;
  datav->base = NULL;
  datav->len = 0;

  return 0;
}

static int client_write_streams(struct client *c) {
  ngtcp2_tstamp ts = timestamp();
  ngtcp2_pkt_info pi;
  ngtcp2_ssize nwrite;
  uint8_t buf[1452];
  ngtcp2_path_storage ps;
  ngtcp2_vec datav;
  size_t datavcnt;
  int64_t stream_id;
  ngtcp2_ssize wdatalen;
  uint32_t flags;
  int fin;

  ngtcp2_path_storage_zero(&ps);

  for (;;) {
    datavcnt = client_get_message(c, &stream_id, &fin, &datav, 1);

    flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    if (fin) {
      flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    }

    nwrite = ngtcp2_conn_writev_stream(c->conn, &ps.path, &pi, buf, sizeof(buf),
                                       &wdatalen, flags, stream_id, &datav,
                                       datavcnt, ts);
    if (nwrite < 0) {
      switch (nwrite) {
      case NGTCP2_ERR_WRITE_MORE:
        c->stream.nwrite += (size_t)wdatalen;
        continue;
      default:
        ESP_LOGE(TAG, "ngtcp2_conn_writev_stream: %s", ngtcp2_strerror((int)nwrite));
        ngtcp2_ccerr_set_liberr(&c->last_error, (int)nwrite, NULL, 0);
        return -1;
      }
    }

    if (nwrite == 0) {
      return 0;
    }

    if (wdatalen > 0) {
      c->stream.nwrite += (size_t)wdatalen;
    }

    if (client_send_packet(c, buf, (size_t)nwrite) != 0) {
      break;
    }
  }

  return 0;
}

static int client_handle_expiry(struct client *c);
static int client_write(struct client *c) {
  ngtcp2_tstamp expiry, now;
  ev_tstamp t;

  if (client_write_streams(c) != 0) {
    return -1;
  }

  expiry = ngtcp2_conn_get_expiry(c->conn);
  now = timestamp();

  // @FIXME: timer has some issues here
  ESP_LOGD(TAG, "check timeout: expiry %lu, now: %lu", expiry, now);
  t = expiry < now ? 1e-9 : (ev_tstamp)(expiry - now) / NGTCP2_SECONDS;
  
  // Ensure minimum timer interval to prevent excessive CPU usage
  if (t < 0.001) {  // Minimum 1ms
    t = 0.001;
    client_handle_expiry(c);
  }

  c->timer.repeat = t;
  ev_timer_again(EV_DEFAULT, &c->timer);

  return 0;
}

static int client_handle_expiry(struct client *c) {
  int rv = ngtcp2_conn_handle_expiry(c->conn, timestamp());
  if (rv != 0) {
    ESP_LOGE(TAG, "ngtcp2_conn_handle_expiry: %s", ngtcp2_strerror(rv));
    return -1;
  }

  return 0;
}

static void client_close(struct client *c) {
  ngtcp2_ssize nwrite;
  ngtcp2_pkt_info pi;
  ngtcp2_path_storage ps;
  uint8_t buf[1280];

  if (ngtcp2_conn_in_closing_period(c->conn) ||
      ngtcp2_conn_in_draining_period(c->conn)) {
    goto fin;
  }

  ngtcp2_path_storage_zero(&ps);

  nwrite = ngtcp2_conn_write_connection_close(
    c->conn, &ps.path, &pi, buf, sizeof(buf), &c->last_error, timestamp());
  if (nwrite < 0) {
    ESP_LOGE(TAG, "ngtcp2_conn_write_connection_close: %s", ngtcp2_strerror((int)nwrite));
    goto fin;
  }

  client_send_packet(c, buf, (size_t)nwrite);

fin:
  ev_break(EV_DEFAULT, EVBREAK_ALL);
}

static void read_cb(struct ev_loop *loop, ev_io *w, int revents) {
  struct client *c = w->data;
  (void)loop;
  (void)revents;

  if (client_read(c) != 0) {
    client_close(c);
    return;
  }

  // Brief delay to avoid collision and allow other tasks to run
  vTaskDelay(pdMS_TO_TICKS(2));

  /* To make it simple, just have one writer thread in timer_cb
  if (client_write(c) != 0) {
    client_close(c);
  }
  */
}

static void timer_cb(struct ev_loop *loop, ev_timer *w, int revents) {
  struct client *c = w->data;
  (void)loop;
  (void)revents;

  if (client_handle_expiry(c) != 0) {
    client_close(c);
    return;
  }

  if (client_write(c) != 0) {
    client_close(c);
  }
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref) {
  struct client *c = conn_ref->user_data;
  return c->conn;
}

static int client_init(struct client *c) {
  struct sockaddr_storage remote_addr, local_addr;
  socklen_t remote_addrlen, local_addrlen = sizeof(local_addr);

  memset(c, 0, sizeof(*c));

  ngtcp2_ccerr_default(&c->last_error);

  c->fd = create_sock((struct sockaddr *)&remote_addr, &remote_addrlen,
                      g_config.hostname, g_config.port);
  if (c->fd == -1) {
    return -1;
  }

  if (connect_sock((struct sockaddr *)&local_addr, &local_addrlen, c->fd,
                   (struct sockaddr *)&remote_addr, remote_addrlen) != 0) {
    return -1;
  }

  memcpy(&c->local_addr, &local_addr, sizeof(c->local_addr));
  c->local_addrlen = local_addrlen;

  if (client_ssl_init(c) != 0) {
    return -1;
  }

  if (client_quic_init(c, (struct sockaddr *)&remote_addr, remote_addrlen,
                       (struct sockaddr *)&local_addr, local_addrlen) != 0) {
    return -1;
  }

  c->stream.stream_id = -1;

  c->conn_ref.get_conn = get_conn;
  c->conn_ref.user_data = c;

  ev_io_init(&c->rev, read_cb, c->fd, EV_READ);
  c->rev.data = c;
  ev_io_start(EV_DEFAULT, &c->rev);

  ev_timer_init(&c->timer, timer_cb, 0., 0.);
  c->timer.data = c;

  return 0;
}

static void client_free(struct client *c) {
  ngtcp2_conn_del(c->conn);
  SSL_free(c->ssl);
  SSL_CTX_free(c->ssl_ctx);
}

static ssize_t client_write_application_data(struct client *c, const uint8_t *data, size_t datalen) {
    if (!c || !c->conn || !data || datalen == 0) {
        ESP_LOGE(TAG, "Invalid parameters for client_write_application_data");
        return -1;
    }

    // This function should write application data to a QUIC stream
    ngtcp2_vec vec = {
        .base = (uint8_t *)data,
        .len = datalen
    };
    
    int64_t stream_id = -1;  // Use the appropriate stream ID or create a new one
    
    // Check if we have an existing stream or need to create one
    if (c->stream.stream_id < 0) {
        int rv = ngtcp2_conn_open_bidi_stream(c->conn, &stream_id, NULL);
        if (rv != 0) {
            ESP_LOGE(TAG, "ngtcp2_conn_open_bidi_stream: %s", ngtcp2_strerror(rv));
            return -1;
        }
        c->stream.stream_id = stream_id;
        ESP_LOGI(TAG, "Opened new QUIC stream with ID: %lld", (long long)stream_id);
    } else {
        stream_id = c->stream.stream_id;
    }
    
    // Use the higher-level write function that handles buffering
    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
    ngtcp2_ssize wdatalen = 0;
    
    uint8_t buf[1452];  // MTU-sized buffer
    ngtcp2_path_storage ps;
    ngtcp2_pkt_info pi;
    
    ngtcp2_path_storage_zero(&ps);

    bool retry = false;
    do {
      ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(c->conn, &ps.path, &pi, buf, sizeof(buf),
                                                      &wdatalen, flags, stream_id, &vec, 1, timestamp());
      if (nwrite < 0) {
        if (nwrite == NGTCP2_ERR_WRITE_MORE) {
          // Partial write, this is normal
          ESP_LOGI(TAG, "Partial write: %zu bytes queued", (size_t)wdatalen);
        } else {
          ESP_LOGE(TAG, "ngtcp2_conn_writev_stream: %s", ngtcp2_strerror((int)nwrite));
          return -1;
        }
      }

      // Send the packet if we have data to send
      if (nwrite > 0) {
        if (client_send_packet(c, buf, (size_t)nwrite) != 0) {
          ESP_LOGE(TAG, "client_send_packet failed");
          return -1;
        }
        ESP_LOGI(TAG, "Sent QUIC packet with %zu bytes, stream data: %lu bytes", (size_t)nwrite, wdatalen);
      }

      if (nwrite == 0)
      {
        ESP_LOGI(TAG, "Cannot send QUIC packet with %zu bytes, stream data: %zu bytes", (size_t)nwrite, (size_t)wdatalen);
      }

      // retry when NO STREAM Frame is sent
      // it happens when ngtpc2 cannot fit a STREAM frame in the buf that we sent
      retry = wdatalen == -1;
    } while(retry);

    return 0;
}

int client_read_application_data(struct client *c, uint8_t *buffer, size_t buffer_size, size_t *bytes_read) {
    *bytes_read = 0;
    
    // First check if we have data in our buffer
    if (app_recv_buffer_len > app_recv_buffer_read_pos) {
        // We have unread data in the buffer
        size_t available = app_recv_buffer_len - app_recv_buffer_read_pos;
        size_t to_copy = (available < buffer_size) ? available : buffer_size;
        
        memcpy(buffer, app_recv_buffer + app_recv_buffer_read_pos, to_copy);
        app_recv_buffer_read_pos += to_copy;
        
        // Reset buffer if all data has been read
        if (app_recv_buffer_read_pos >= app_recv_buffer_len) {
            app_recv_buffer_len = 0;
            app_recv_buffer_read_pos = 0;
        }
        
        *bytes_read = to_copy;
        return 0;
    }
    
    // We DONT need to read from the network
    // We have another async reader,
    // For demo, this is good for now.
    /*
    if (client_read(c) != 0) {
        ESP_LOGE(TAG, "client_read failed");
        return -1;
    }
    
    // Check if we received any application data during client_read
    if (app_recv_buffer_len > 0) {
        // We have data in the buffer now, call ourselves recursively
        return client_read_application_data(c, buffer, buffer_size, bytes_read);
    }
    */
    // No data available at this time
    return -2;  // Special code for no data
}

int recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                    int64_t stream_id, uint64_t offset,
                    const uint8_t *data, size_t datalen,
                    void *user_data, void *stream_user_data) {

    // Store the received data in our buffer
    if (datalen > 0 && app_recv_buffer_len + datalen <= APP_BUFFER_SIZE) {
        memcpy(app_recv_buffer + app_recv_buffer_len, data, datalen);
        app_recv_buffer_len += datalen;
    }
    
    // Acknowledge the data was received by using ngtcp2_conn_extend_max_stream_offset
    int rv = ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
    if (rv != 0) {
        ESP_LOGE(TAG, "ngtcp2_conn_extend_max_stream_offset: %s", ngtcp2_strerror(rv));
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    
    return 0;
}

// Non-blocking QUIC client functions
int quic_client_init_with_config(const quic_client_config_t *config) {
    // Initialize mutex for thread safety
    if (quic_mutex == NULL) {
        quic_mutex = xSemaphoreCreateMutex();
        if (quic_mutex == NULL) {
            ESP_LOGE(TAG, "Failed to create QUIC mutex");
            return -1;
        }
        ESP_LOGI(TAG, "QUIC mutex created successfully");
    }
    
    // Clear the global client structure first
    memset(&g_client, 0, sizeof(g_client));
    quic_processing = false;
    
    if (config) {
        g_config.hostname = config->hostname;
        g_config.port = config->port;
        g_config.alpn = config->alpn;
        ESP_LOGI(TAG, "QUIC client config: %s:%s with ALPN %s", 
               g_config.hostname, g_config.port, g_config.alpn);
    }

    ESP_LOGI(TAG, "init random number generator");
    srandom((unsigned int)timestamp());

    // Initialize the event loop (non-blocking)
    ev_default_loop_init();
    
    ESP_LOGI(TAG, "init client ...");

    if (client_init(&g_client) != 0) {
        ESP_LOGE(TAG, "client_init failed");
        return -1;
    }

    g_quic_connected = false;
    g_quic_handshake_completed = false;
    
    ESP_LOGI(TAG, "QUIC client initialization completed");
    return 0;
}

int quic_client_process(void) {
    // Use delay to prevent watchdog trigger
    vTaskDelay(pdMS_TO_TICKS(5));
    
    // Check if mutex is available
    if (quic_mutex == NULL) {
        ESP_LOGE(TAG, "QUIC mutex not initialized");
        return -1;
    }
    
    // Try to acquire mutex with timeout (50ms)
    if (xSemaphoreTake(quic_mutex, pdMS_TO_TICKS(50)) != pdTRUE) {
        ESP_LOGE(TAG, "Failed to acquire QUIC mutex, skipping this cycle");
        return 0; // Don't consider this an error, just skip
    }
    
    int result = 0;
    
    // Check if already processing to prevent reentrancy
    if (quic_processing) {
        ESP_LOGI(TAG, "QUIC processing already in progress, skipping");
        xSemaphoreGive(quic_mutex);
        return 0;
    }
    
    // Set processing flag
    quic_processing = true;
    
    // Check if we have a valid connection
    if (!g_client.conn) {
        result = -1;
        goto cleanup;
    }
    
    // Check connection state before processing
    if (ngtcp2_conn_in_closing_period(g_client.conn) || 
        ngtcp2_conn_in_draining_period(g_client.conn)) {
        ESP_LOGI(TAG, "Connection is closing/draining, skipping processing");
        result = -1;
        goto cleanup;
    }


    // Read from the socket and handle packets
    result = client_read(&g_client);
    if (result != 0) {
        ESP_LOGE(TAG, "client_read failed: %d", result);
        goto cleanup;
    }
    
    // Brief delay between read and write
    vTaskDelay(pdMS_TO_TICKS(1));
    
    // Write any pending data
    result = client_write(&g_client);
    if (result != 0) {
        ESP_LOGE(TAG, "client_write failed: %d", result);
        goto cleanup;
    }

    // Update connection state
    if (g_client.conn && !g_quic_handshake_completed) {
        g_quic_handshake_completed = true;
        g_quic_connected = true;
        ESP_LOGI(TAG, "QUIC connection established!");
    }

cleanup:
    quic_processing = false;
    xSemaphoreGive(quic_mutex);
    return result;
}

bool quic_client_is_connected(void) {
    return g_quic_connected && g_quic_handshake_completed && g_client.conn != NULL;
}

int quic_client_local_stream_avail(void) {
    return g_quic_n_local_streams > 0;
}

void quic_client_cleanup(void) {
    ESP_LOGI(TAG, "Cleaning up QUIC client...");
    
    // Acquire mutex before cleanup
    if (quic_mutex != NULL) {
        xSemaphoreTake(quic_mutex, portMAX_DELAY);
    }
    
    if (g_client.conn) {
        ESP_LOGI(TAG, "Freeing QUIC connection...");
        client_free(&g_client);
        memset(&g_client, 0, sizeof(g_client));  // Clear the structure
    }
    
    g_quic_connected = false;
    g_quic_handshake_completed = false;
    quic_processing = false;
    
    // Release and delete mutex
    if (quic_mutex != NULL) {
        xSemaphoreGive(quic_mutex);
        vSemaphoreDelete(quic_mutex);
        quic_mutex = NULL;
        ESP_LOGI(TAG, "QUIC mutex deleted");
    }
    
    ESP_LOGI(TAG, "QUIC client cleanup completed. Free heap: %lu bytes", esp_get_free_heap_size());
}

// Thread-safe wrapper for QUIC write operations
int quic_client_write_safe(const uint8_t *data, size_t datalen) {
    if (quic_mutex == NULL) {
        ESP_LOGE(TAG, "QUIC mutex not initialized");
        return -1;
    }
    
    if (data == NULL || datalen == 0) {
        ESP_LOGE(TAG, "Invalid write parameters");
        return -1;
    }
    
    // Acquire mutex with timeout
    if (xSemaphoreTake(quic_mutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
        ESP_LOGE(TAG, "Failed to acquire QUIC mutex for write");
        return -1;
    }
    
    int result = -1;
    
    // Check if connection is valid
    if (!g_client.conn || !g_quic_connected) {
        ESP_LOGE(TAG, "QUIC connection not ready for write");
        goto cleanup;
    }
    
    // Check if processing is ongoing
    if (quic_processing) {
        ESP_LOGE(TAG, "QUIC processing in progress, cannot write");
        goto cleanup;
    }
    
    // Perform the write operation
    result = client_write_application_data(&g_client, data, datalen);
    if (result == 0) {
        ESP_LOGI(TAG, "Successfully wrote %zu bytes to QUIC stream", datalen);
    } else {
        ESP_LOGE(TAG, "Failed to write data to QUIC stream: %d", result);
    }

cleanup:
    xSemaphoreGive(quic_mutex);
    return result;
}

// Thread-safe wrapper for QUIC read operations
int quic_client_read_safe(uint8_t *buffer, size_t buffer_size, size_t *bytes_read) {
    if (quic_mutex == NULL) {
        ESP_LOGE(TAG, "QUIC mutex not initialized");
        return -1;
    }
    
    if (buffer == NULL || buffer_size == 0 || bytes_read == NULL) {
        ESP_LOGE(TAG, "Invalid read parameters");
        return -1;
    }
    
    *bytes_read = 0;
    
    // Acquire mutex with timeout
    if (xSemaphoreTake(quic_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        ESP_LOGE(TAG, "Failed to acquire QUIC mutex for read");
        return -1;
    }
    
    int result = client_read_application_data(&g_client, buffer, buffer_size, bytes_read);
    
    // Release mutex
    xSemaphoreGive(quic_mutex);
    
    return result;
}
