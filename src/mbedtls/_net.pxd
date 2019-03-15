"""Declarations from `mbedtls/net_sockets.h`."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2018, Mathias Laurin"
__license__ = "MIT License"


cdef:
    enum: MBEDTLS_NET_PROTO_TCP = 0
    enum: MBEDTLS_NET_PROTO_UDP = 1


cdef extern from "mbedtls/net_sockets.h" nogil:
    ctypedef struct mbedtls_net_context:
        int fd

    void mbedtls_net_init(mbedtls_net_context *ctx)
    void mbedtls_net_free(mbedtls_net_context *ctx)
    int mbedtls_net_connect(
        mbedtls_net_context *ctx,
        const char *host, const char *port,
        int proto)
    int mbedtls_net_bind(
        mbedtls_net_context *ctx,
        const char *bind_ip,
        const char *port,
        int proto)
    int mbedtls_net_accept(
        mbedtls_net_context *bind_ctx,
        mbedtls_net_context *client_ctx,
        void *client_ip, size_t buf_size, size_t *ip_len)
    int mbedtls_net_set_block(mbedtls_net_context *ctx)
    int mbedtls_net_set_nonblock(mbedtls_net_context *ctx)
    # mbedtls_net_usleep
    int mbedtls_net_recv(void *ctx, unsigned char *buf, size_t len)
    int mbedtls_net_send(void *ctx, const unsigned char *buf, size_t len)
    int mbedtls_net_recv_timeout(
        void *ctx,
        unsigned char *buf, size_t len,
        int timeout)
