#pragma once

#include "common/osdep.h"
#include <winsock2.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tls_ctx tls_ctx_t;

/* Perform a TLS handshake over an already-connected socket. host is the
   SNI / certificate hostname to validate. If no_verify is non-zero,
   certificate chain validation is skipped (for pools that don't send a
   complete chain). Returns NULL on failure. */
tls_ctx_t *tls_connect(SOCKET sock, const char *host, int no_verify);

/* Encrypted send/recv over the established TLS session. Return bytes
   transferred, or -1 on error. tls_recv blocks until at least 1 byte
   is available (or connection closes). */
int tls_send(tls_ctx_t *t, const void *buf, int len);
int tls_recv(tls_ctx_t *t, void *buf, int len);

void tls_close(tls_ctx_t *t);

#ifdef __cplusplus
}
#endif
