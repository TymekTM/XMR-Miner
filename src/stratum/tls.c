#include "tls.h"
#include "common/log.h"

#define SECURITY_WIN32
#include <windows.h>
#include <schannel.h>
#include <security.h>
#include <sspi.h>
#include <winsock2.h>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "credui.lib")

#define TLS_RECV_BUF 16384

struct tls_ctx {
    SOCKET sock;
    CredHandle hcred;
    CtxtHandle hctx;
    SecPkgContext_StreamSizes sizes;
    int have_sizes;
    int established;

    /* encrypted recv staging */
    unsigned char enc[TLS_RECV_BUF];
    int enc_len;

    /* decrypted plaintext not yet handed to caller */
    unsigned char dec[TLS_RECV_BUF];
    int dec_len;
    int dec_off;
};

/* Receive some encrypted bytes from the socket (blocking until data). */
static int raw_recv(SOCKET s, void *buf, int len) {
    int total = 0;
    while (total < len) {
        int n = recv(s, (char *)buf + total, len - total, 0);
        if (n <= 0) return -1;
        total += n;
    }
    return total;
}

/* Send all bytes. */
static int raw_send_all(SOCKET s, const void *buf, int len) {
    int total = 0;
    while (total < len) {
        int n = send(s, (const char *)buf + total, len - total, 0);
        if (n <= 0) return -1;
        total += n;
    }
    return total;
}

static void secbuf_init(SecBuffer *b, unsigned long type, void *pv, unsigned long len) {
    b->BufferType = type;
    b->pvBuffer = pv;
    b->cbBuffer = len;
}

tls_ctx_t *tls_connect(SOCKET sock, const char *host, int no_verify) {
    SECURITY_STATUS sret;

    tls_ctx_t *t = (tls_ctx_t *)calloc(1, sizeof(tls_ctx_t));
    if (!t) return NULL;
    t->sock = sock;

    TimeStamp expiry;
    SCHANNEL_CRED cred;
    ZeroMemory(&cred, sizeof(cred));
    cred.dwVersion = SCHANNEL_CRED_VERSION;
    cred.grbitEnabledProtocols = 0;            /* let OS pick TLS 1.2/1.3 */
    cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SERVERNAME_CHECK;
    if (no_verify)
        cred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;

    sret = AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND,
                                     NULL, &cred, NULL, NULL, &t->hcred, &expiry);
    if (sret != SEC_E_OK) {
        LOG_ERR("[TLS] AcquireCredentialsHandle failed: 0x%lx", sret);
        free(t);
        return NULL;
    }

    unsigned long reqflags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                             ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY |
                             ISC_REQ_STREAM;
    unsigned long outflags = 0;

    /* First handshake call: no input token. */
    SecBufferDesc outdesc;
    SecBuffer outbuf[2];
    outdesc.ulVersion = SECBUFFER_VERSION;
    outdesc.cBuffers = 2;
    outdesc.pBuffers = outbuf;
    secbuf_init(&outbuf[0], SECBUFFER_TOKEN, NULL, 0);
    secbuf_init(&outbuf[1], SECBUFFER_EMPTY, NULL, 0);

    sret = InitializeSecurityContextA(&t->hcred, NULL, host, reqflags,
            0, SECURITY_NATIVE_DREP, NULL, 0, &t->hctx, &outdesc, &outflags, &expiry);
    if (outbuf[0].cbBuffer > 0 && outbuf[0].pvBuffer) {
        raw_send_all(t->sock, outbuf[0].pvBuffer, (int)outbuf[0].cbBuffer);
        FreeContextBuffer(outbuf[0].pvBuffer);
    }
    if (sret != SEC_I_CONTINUE_NEEDED && sret != SEC_E_OK) {
        LOG_ERR("[TLS] handshake init failed: 0x%lx", sret);
        FreeCredentialHandle(&t->hcred);
        free(t);
        return NULL;
    }

    /* Subsequent rounds: feed server tokens, send our tokens. */
    while (sret == SEC_I_CONTINUE_NEEDED) {
        if (t->enc_len == 0) {
            int n = recv(t->sock, (char *)t->enc, sizeof(t->enc), 0);
            if (n <= 0) {
                LOG_ERR("[TLS] handshake recv failed");
                DeleteSecurityContext(&t->hctx);
                FreeCredentialHandle(&t->hcred);
                free(t);
                return NULL;
            }
            t->enc_len = n;
        }

        SecBufferDesc indesc;
        SecBuffer inbuf[2];
        indesc.ulVersion = SECBUFFER_VERSION;
        indesc.cBuffers = 2;
        indesc.pBuffers = inbuf;
        secbuf_init(&inbuf[0], SECBUFFER_TOKEN, t->enc, t->enc_len);
        secbuf_init(&inbuf[1], SECBUFFER_EMPTY, NULL, 0);

        SecBufferDesc outdesc2;
        SecBuffer outbuf2[2];
        outdesc2.ulVersion = SECBUFFER_VERSION;
        outdesc2.cBuffers = 2;
        outdesc2.pBuffers = outbuf2;
        secbuf_init(&outbuf2[0], SECBUFFER_TOKEN, NULL, 0);
        secbuf_init(&outbuf2[1], SECBUFFER_EMPTY, NULL, 0);

        sret = InitializeSecurityContextA(&t->hcred, &t->hctx, host, reqflags,
                0, SECURITY_NATIVE_DREP, &indesc, 0, &t->hctx, &outdesc2, &outflags, &expiry);

        if (outbuf2[0].cbBuffer > 0 && outbuf2[0].pvBuffer) {
            raw_send_all(t->sock, outbuf2[0].pvBuffer, (int)outbuf2[0].cbBuffer);
            FreeContextBuffer(outbuf2[0].pvBuffer);
        }

        if (sret == SEC_E_OK || sret == SEC_I_CONTINUE_NEEDED) {
            /* consume the bytes ISC actually processed; keep any EXTRA */
            if (inbuf[1].BufferType == SECBUFFER_EXTRA && inbuf[1].cbBuffer > 0) {
                int extra = (int)inbuf[1].cbBuffer;
                memmove(t->enc, t->enc + (t->enc_len - extra), extra);
                t->enc_len = extra;
            } else {
                t->enc_len = 0;
            }
        }
        if (sret == SEC_E_INCOMPLETE_MESSAGE) {
            /* partial record: keep what we have and recv more next loop */
            continue;
        }
        if (sret != SEC_E_OK && sret != SEC_I_CONTINUE_NEEDED) {
            LOG_ERR("[TLS] handshake failed: 0x%lx", sret);
            DeleteSecurityContext(&t->hctx);
            FreeCredentialHandle(&t->hcred);
            free(t);
            return NULL;
        }
    }

    t->established = 1;
    t->enc_len = 0;
    LOG_DEBUG("[TLS] handshake loop exited, final sret=0x%lx", sret);

    sret = QueryContextAttributesA(&t->hctx, SECPKG_ATTR_STREAM_SIZES, &t->sizes);
    if (sret != SEC_E_OK) {
        LOG_ERR("[TLS] QueryContextAttributes(STREAM_SIZES) failed: 0x%lx", sret);
        DeleteSecurityContext(&t->hctx);
        FreeCredentialHandle(&t->hcred);
        free(t);
        return NULL;
    }
    t->have_sizes = 1;

    LOG_INFO("[TLS] Handshake OK (host=%s) header=%lu trailer=%lu maxmsg=%lu",
             host ? host : "(none)",
             t->sizes.cbHeader, t->sizes.cbTrailer, t->sizes.cbMaximumMessage);
    return t;
}

int tls_send(tls_ctx_t *t, const void *buf, int len) {
    if (!t || !t->established) return -1;

    int header = (int)t->sizes.cbHeader;
    int trailer = (int)t->sizes.cbTrailer;
    int max_msg = (int)t->sizes.cbMaximumMessage;

    int sent = 0;
    const char *p = (const char *)buf;
    while (sent < len) {
        int chunk = len - sent;
        if (chunk > max_msg) chunk = max_msg;

        int total = header + chunk + trailer;
        unsigned char *wire = (unsigned char *)malloc(total);
        if (!wire) return -1;
        memcpy(wire + header, p + sent, chunk);

        SecBufferDesc desc;
        SecBuffer bufs[4];
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers = 4;
        desc.pBuffers = bufs;
        secbuf_init(&bufs[0], SECBUFFER_STREAM_HEADER, wire, header);
        secbuf_init(&bufs[1], SECBUFFER_DATA, wire + header, chunk);
        secbuf_init(&bufs[2], SECBUFFER_STREAM_TRAILER, wire + header + chunk, trailer);
        secbuf_init(&bufs[3], SECBUFFER_EMPTY, NULL, 0);

        SECURITY_STATUS sret = EncryptMessage(&t->hctx, 0, &desc, 0);
        if (sret != SEC_E_OK) {
            LOG_ERR("[TLS] EncryptMessage failed: 0x%lx", sret);
            free(wire);
            return -1;
        }
        int wire_len = (int)(bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer);
        if (raw_send_all(t->sock, wire, wire_len) < 0) {
            free(wire);
            return -1;
        }
        free(wire);
        sent += chunk;
    }
    return sent;
}

/* Decrypt one record from the staging buffer. Returns >0 plaintext bytes now
   available in t->dec, 0 if more encrypted data is needed, -1 on fatal error. */
static int decrypt_next(tls_ctx_t *t) {
    if (t->dec_len - t->dec_off > 0) return (t->dec_len - t->dec_off);

    t->dec_len = 0;
    t->dec_off = 0;

    SecBufferDesc desc;
    SecBuffer bufs[4];
    desc.ulVersion = SECBUFFER_VERSION;
    desc.cBuffers = 4;
    desc.pBuffers = bufs;
    secbuf_init(&bufs[0], SECBUFFER_DATA, t->enc, t->enc_len);
    secbuf_init(&bufs[1], SECBUFFER_EMPTY, NULL, 0);
    secbuf_init(&bufs[2], SECBUFFER_EMPTY, NULL, 0);
    secbuf_init(&bufs[3], SECBUFFER_EMPTY, NULL, 0);

    SECURITY_STATUS sret = DecryptMessage(&t->hctx, &desc, 0, NULL);
    if (sret == SEC_E_OK) {
        int plain = (int)bufs[1].cbBuffer;
        if (plain > (int)sizeof(t->dec)) plain = (int)sizeof(t->dec);
        memcpy(t->dec, bufs[1].pvBuffer, plain);
        t->dec_len = plain;
        t->dec_off = 0;

        /* shift unconsumed encrypted bytes */
        int consumed = t->enc_len;
        if (bufs[3].BufferType == SECBUFFER_EXTRA && bufs[3].cbBuffer > 0) {
            int extra = (int)bufs[3].cbBuffer;
            memmove(t->enc, t->enc + (t->enc_len - extra), extra);
            t->enc_len = extra;
        } else {
            t->enc_len = 0;
        }
        (void)consumed;
        return plain;
    }
    if (sret == SEC_E_INCOMPLETE_MESSAGE) {
        return 0;  /* need more bytes */
    }
    LOG_ERR("[TLS] DecryptMessage failed: 0x%lx", sret);
    return -1;
}

int tls_recv(tls_ctx_t *t, void *buf, int len) {
    if (!t || !t->established) return -1;

    /* serve leftover plaintext first */
    if (t->dec_len - t->dec_off > 0) {
        int n = t->dec_len - t->dec_off;
        if (n > len) n = len;
        memcpy(buf, t->dec + t->dec_off, n);
        t->dec_off += n;
        return n;
    }

    for (;;) {
        int r = decrypt_next(t);
        if (r > 0) {
            int n = t->dec_len - t->dec_off;
            if (n > len) n = len;
            memcpy(buf, t->dec + t->dec_off, n);
            t->dec_off += n;
            return n;
        }
        if (r < 0) return -1;

        /* r == 0: need more encrypted bytes */
        if (t->enc_len >= (int)sizeof(t->enc) - 1) {
            LOG_ERR("[TLS] encrypted buffer overflow");
            return -1;
        }
        int got = recv(t->sock, (char *)t->enc + t->enc_len,
                       (int)sizeof(t->enc) - t->enc_len, 0);
        if (got <= 0) return -1;
        t->enc_len += got;
    }
}

void tls_close(tls_ctx_t *t) {
    if (!t) return;
    if (t->established) {
        /* Best-effort TLS close-notify. SChannel shutdown is finicky and not
           required for correctness; if anything here fails we just proceed to
           tear down the context. */
        __try {
            DWORD type = SCHANNEL_SHUTDOWN;
            SecBufferDesc desc;
            SecBuffer sbuf;
            desc.ulVersion = SECBUFFER_VERSION;
            desc.cBuffers = 1;
            desc.pBuffers = &sbuf;
            secbuf_init(&sbuf, SECBUFFER_TOKEN, &type, sizeof(type));
            if (ApplyControlToken(&t->hctx, &desc) == SEC_E_OK) {
                SecBufferDesc odesc;
                SecBuffer obuf;
                unsigned char tmp[128];
                odesc.ulVersion = SECBUFFER_VERSION;
                odesc.cBuffers = 1;
                odesc.pBuffers = &obuf;
                secbuf_init(&obuf, SECBUFFER_TOKEN, tmp, sizeof(tmp));
                DWORD outflags = 0;
                TimeStamp expiry;
                if (InitializeSecurityContextA(&t->hcred, &t->hctx, NULL, 0, 0,
                       SECURITY_NATIVE_DREP, NULL, 0, &t->hctx, &odesc, &outflags,
                       &expiry) == SEC_E_OK && obuf.cbBuffer > 0) {
                    send(t->sock, (const char *)obuf.pvBuffer, (int)obuf.cbBuffer, 0);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { /* ignore */ }
        DeleteSecurityContext(&t->hctx);
    }
    FreeCredentialHandle(&t->hcred);
    free(t);
}
