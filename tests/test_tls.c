/* Minimal TLS handshake smoke test: connects to a TLS server and verifies
   the SChannel handshake works. Does not mine. Default target google.com:443. */
#include "stratum/tls.h"
#include "common/log.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")

int main(int argc, char **argv) {
    const char *host = (argc > 1) ? argv[1] : "google.com";
    const char *port = (argc > 2) ? argv[2] : "443";

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) {
        printf("[FAIL] DNS resolve failed for %s\n", host);
        return 1;
    }

    SOCKET sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (connect(sock, res->ai_addr, (int)res->ai_addrlen) != 0) {
        printf("[FAIL] connect failed: %d\n", WSAGetLastError()); fflush(stdout);
        freeaddrinfo(res);
        return 1;
    }
    freeaddrinfo(res);
    printf("[OK]   TCP connected to %s:%s\n", host, port); fflush(stdout);

    tls_ctx_t *t = tls_connect(sock, host, 0);
    if (!t) {
        printf("[FAIL] TLS handshake failed\n"); fflush(stdout);
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    /* round-trip: send a minimal HTTP HEAD, read some response */
    const char *req = "HEAD / HTTP/1.0\r\nHost: ";
    char buf[512];
    int len = snprintf(buf, sizeof(buf), "%s%s\r\n\r\n", req, host);
    printf("[..]   calling tls_send...\n"); fflush(stdout);
    int sent = tls_send(t, buf, len);
    printf("[OK]   tls_send returned %d (asked %d)\n", sent, len); fflush(stdout);

    char rbuf[512] = {0};
    int got = tls_recv(t, rbuf, (int)sizeof(rbuf) - 1);
    printf("[..]   tls_recv returned %d\n", got); fflush(stdout);
    if (got > 0) {
        rbuf[got < (int)sizeof(rbuf) ? got : (int)sizeof(rbuf) - 1] = '\0';
        printf("[OK]   tls_recv returned %d bytes\n", got);
        /* show first line of response */
        char *nl = strchr(rbuf, '\r');
        if (nl) *nl = '\0';
        printf("[OK]   response: %.60s\n", rbuf);
        printf("\n[PASS] TLS send/recv verified\n");
    } else {
        printf("[FAIL] tls_recv returned %d\n", got);
    }

    tls_close(t);
    closesocket(sock);
    WSACleanup();
    return (got > 0) ? 0 : 1;
}
