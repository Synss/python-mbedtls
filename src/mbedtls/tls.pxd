"""Declarations from `mbedtls/ssl.h`."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2018, Mathias Laurin"
__license__ = "MIT License"


cimport mbedtls._net as _net
cimport mbedtls._ringbuf as _rb
cimport mbedtls.pk as _pk
cimport mbedtls.x509 as _x509


cdef:
    enum:
        MBEDTLS_SSL_TRANSPORT_STREAM = 0
        MBEDTLS_SSL_TRANSPORT_DATAGRAM = 1

    enum:
        MBEDTLS_SSL_PRESET_DEFAULT = 0
        MBEDTLS_SSL_PRESET_SUITEB = 2

    enum:
        MBEDTLS_SSL_VERIFY_NONE = 0
        MBEDTLS_SSL_VERIFY_OPTIONAL = 1
        MBEDTLS_SSL_VERIFY_REQUIRED = 2

    enum:
        MBEDTLS_SSL_ANTI_REPLAY_DISABLED = 0
        MBEDTLS_SSL_ANTI_REPLAY_ENABLED = 1

    enum: MBEDTLS_SSL_MAJOR_VERSION_3 = 3

    enum:
        MBEDTLS_SSL_MINOR_VERSION_0 = 0
        MBEDTLS_SSL_MINOR_VERSION_1 = 1
        MBEDTLS_SSL_MINOR_VERSION_2 = 2
        MBEDTLS_SSL_MINOR_VERSION_3 = 3

    enum:
        # Message type
        MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC = 20  # 0x14
        MBEDTLS_SSL_MSG_ALERT = 21      # 0x15
        MBEDTLS_SSL_MSG_HANDSHAKE = 22  # 0x16
        MBEDTLS_SSL_MSG_APPLICATION_DATA = 23  # 0x17

    enum:
        MBEDTLS_SSL_HELLO_REQUEST
        MBEDTLS_SSL_CLIENT_HELLO
        MBEDTLS_SSL_SERVER_HELLO
        MBEDTLS_SSL_SERVER_CERTIFICATE
        MBEDTLS_SSL_SERVER_KEY_EXCHANGE
        MBEDTLS_SSL_CERTIFICATE_REQUEST
        MBEDTLS_SSL_SERVER_HELLO_DONE
        MBEDTLS_SSL_CLIENT_CERTIFICATE
        MBEDTLS_SSL_CLIENT_KEY_EXCHANGE
        MBEDTLS_SSL_CERTIFICATE_VERIFY
        MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC
        MBEDTLS_SSL_CLIENT_FINISHED
        MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC
        MBEDTLS_SSL_SERVER_FINISHED
        MBEDTLS_SSL_FLUSH_BUFFERS
        MBEDTLS_SSL_HANDSHAKE_WRAPUP
        MBEDTLS_SSL_HANDSHAKE_OVER
        MBEDTLS_SSL_SERVER_NEW_SESSION_TICKET
        MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT

    enum:
        MBEDTLS_SSL_IS_CLIENT
        MBEDTLS_SSL_IS_SERVER

    enum:
        MBEDTLS_ERR_NET_CONN_RESET = -0x0050
        MBEDTLS_ERR_SSL_WANT_READ = -0x6900
        MBEDTLS_ERR_SSL_WANT_WRITE = -0x6880
        MBEDTLS_ERR_SSL_CLIENT_RECONNECT = -0x6780
        MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY = -0x7880
        MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL = -0x6a00
        MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED = -0x6a80
        MBEDTLS_ERR_SSL_BAD_INPUT_DATA = -0x7100


cdef extern from "mbedtls/debug.h" nogil:
    void mbedtls_debug_set_threshold(int threshold)


cdef extern from "mbedtls/timing.h" nogil:
    # This provides callbacks for DTLS with blocking IO.

    ctypedef struct mbedtls_timing_hr_time:
        pass

    ctypedef struct mbedtls_timing_delay_context:
        mbedtls_timing_hr_time timer
        int int_ms
        int fin_ms

    # extern volatile int mbedtls_timing_alarmed

    # unsigned long mbedtls_timing_hardclock()
    # unsigned long mbedtls_timing_get_timer(
    #     mbedtls_timing_hr_time *,
    #     int reset,
    # )
    # void mbedtls_set_alarm(int seconds)

    # mbedtls_ssl_set_timer_t callback
    void mbedtls_timing_set_delay(void *data, int int_ms, int fin_ms)
    # mbedtls_ssl_get_timer_t callback
    int mbedtls_timing_get_delay(void *data)


cdef extern from "mbedtls/ssl_internal.h" nogil:
    ctypedef struct mbedtls_ssl_transform:
        pass

    ctypedef struct mbedtls_ssl_handshake_params:
        int sig_alg
        int verify_sig_alg
        # Diffie-Hellman key exchange:
        # mbedtls_dhm_context dhm_ctx
        _pk.mbedtls_ecdh_context ecdh_ctx
        # EC-J-Pake (not very much used anymore)
        # mbedtls_ecjpake_context ecjpake_ctx
        mbedtls_ssl_key_cert *key_cert

    ctypedef struct mbedtls_ssl_key_cert:
        _x509.mbedtls_x509_crt *cert
        _pk.mbedtls_pk_context *key
        mbedtls_ssl_key_cert *next


cdef extern from "mbedtls/ssl.h" nogil:
    # Defined here
    # ------------
    # ctypedef enum mbedtls_ssl_states: pass

    ctypedef struct mbedtls_ssl_session:
        pass

    ctypedef struct mbedtls_ssl_config:
        # set_certificate_chain
        mbedtls_ssl_key_cert *key_cert
        # set_ciphers
        const int *ciphersuite_list[4]
        # set_inner_protocols
        const char **alpn_list
        # set_lowest_supported_version/set_highest_supported_version
        unsigned char max_major_ver
        unsigned char max_minor_ver
        unsigned char min_major_ver
        unsigned char min_minor_ver
        # set_anti_replay
        unsigned int anti_replay


        unsigned int endpoint
        unsigned int transport
        # set_validate_certificates
        unsigned int authmode

        # set_trust_store
        _x509.mbedtls_x509_crt *ca_chain
        _x509.mbedtls_x509_crt *ca_crl
        # set_sni_callback
        # f_sni / p_sni

    ctypedef struct mbedtls_ssl_context:
        const mbedtls_ssl_config *conf
        int state
        char *hostname
        unsigned char *cli_id
        size_t cli_id_len

    # Callback types
    # --------------
    ctypedef int(*mbedtls_ssl_send_p)(void*, const unsigned char*, size_t)
    ctypedef int(*mbedtls_ssl_recv_p)(void*, unsigned char*, size_t)
    ctypedef int(*mbedtls_ssl_recv_timeout_p)(
        void*, unsigned char*, size_t, int)

    ctypedef void(*mbedtls_ssl_set_timer_t)(void *ctx, int int_ms, int fin_ms)
    ctypedef int(*mbedtls_ssl_get_timer_t)(void *ctx)
    ctypedef int(*mbedtls_ssl_cookie_write_t)(
        void *ctx,
        unsigned char **p, unsigned char *end,
        const unsigned char *info, size_t ilen)
    ctypedef int(*mbedtls_ssl_cookie_check_t)(
        void *ctx,
        const unsigned char *cookie, size_t clen,
        const unsigned char *info, size_t ilen)
    # mbedtls_ssl_ticket_write_t
    # mbedtls_ssl_ticket_parse_t
    # mbedtls_ssl_export_keys_t

    # Free functions
    # --------------
    const int* mbedtls_ssl_list_ciphersuites()
    const char* mbedtls_ssl_get_ciphersuite_name(const int ciphersuite_id)
    int mbedtls_ssl_get_ciphersuite_id(const char *ciphersuite_name)

    # mbedtls_ssl_config
    # ------------------
    void mbedtls_ssl_conf_endpoint(mbedtls_ssl_config *conf, int endpoint)
    # void mbedtls_ssl_conf_transport(mbedtls_ssl_config *conf, int transport)

    void mbedtls_ssl_conf_authmode(mbedtls_ssl_config *conf, int authmode)
    void mbedtls_ssl_conf_ciphersuites(
        mbedtls_ssl_config *conf,
        const int* ciphersuites)

    # DTLS only
    # ---------
    void mbedtls_ssl_conf_dtls_anti_replay(
        mbedtls_ssl_config *conf,
        char mode)
    # mbedtls_ssl_conf_dtls_badmac_limit
    # mbedtls_ssl_conf_handshake_timeout
    # mbedtls_ssl_conf_ciphersuites_for_version
    # mbedtls_ssl_conf_cert_profile

    # TLS + DTLS
    # ----------
    void mbedtls_ssl_conf_ca_chain(
        mbedtls_ssl_config *conf,
        _x509.mbedtls_x509_crt *ca_chain,
        _x509.mbedtls_x509_crl *ca_crl)
    int mbedtls_ssl_conf_own_cert(
        mbedtls_ssl_config *conf,
        _x509.mbedtls_x509_crt *own_cert,
        _pk.mbedtls_pk_context *pk_key)

    # mbedtls_ssl_conf_psk
    # mbedtls_ssl_conf_dh_param
    # mbedtls_ssl_conf_dh_param_ctx
    # mbedtls_ssl_conf_dhm_min_bitlen
    # mbedtls_ssl_conf_curves
    # mbedtls_ssl_conf_sig_hashes
    int mbedtls_ssl_conf_alpn_protocols(
        mbedtls_ssl_config *conf,
        const char **protos)
    void mbedtls_ssl_config_init(mbedtls_ssl_config *conf)
    int mbedtls_ssl_config_defaults(
        mbedtls_ssl_config *conf,
        int endpoint,
        int transport,
        int preset)
    void mbedtls_ssl_config_free(mbedtls_ssl_config *conf)

    # mbedtls_ssl_config: set callbacks
    # ---------------------------------
    # mbedtls_ssl_conf_verify  // optional

    void mbedtls_ssl_conf_rng(
        mbedtls_ssl_config *conf,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
    void mbedtls_ssl_conf_dbg(
        mbedtls_ssl_config *conf,
        void (*f_dbg)(void *, int, const char *, int, const char *),
        void  *p_dbg )

    # mbedtls_ssl_conf_read_timeout
    # mbedtls_ssl_conf_session_tickets_cb
    # mbedtls_ssl_conf_export_keys_cb

    void mbedtls_ssl_conf_dtls_cookies(
        mbedtls_ssl_config *conf,
        mbedtls_ssl_cookie_write_t f_cookie_write,
        mbedtls_ssl_cookie_check_t f_cookie_check,
        void *p_cookie,
    )

    # mbedtls_ssl_conf_session_cache
    # mbedtls_ssl_conf_psk_cb
    void mbedtls_ssl_conf_sni(
        mbedtls_ssl_config *conf,
        int (*f_sni)(void *, mbedtls_ssl_context *, const unsigned char*,
                     size_t),
        void* p_sni)
    void mbedtls_ssl_conf_max_version(
        mbedtls_ssl_config *conf,
        int major,
        int minor)
    void mbedtls_ssl_conf_min_version(
        mbedtls_ssl_config *conf,
        int major,
        int minor)
    # mbedtls_ssl_conf_fallback
    # mbedtls_ssl_conf_encrypt_then_mac
    # mbedtls_ssl_conf_extended_master_secret
    # mbedtls_ssl_conf_arc4_support
    # mbedtls_ssl_conf_max_frag_len
    # mbedtls_ssl_conf_truncated_hmac
    # mbedtls_ssl_conf_cbc_record_splitting
    # mbedtls_ssl_conf_session_tickets
    void mbedtls_ssl_conf_renegotiation(
        mbedtls_ssl_config *conf,
        int renegotiation)
    # mbedtls_ssl_conf_legacy_renegotiation
    # mbedtls_ssl_conf_renegotiation_enforced
    # mbedtls_ssl_conf_renegotiation_period

    # mbedtls_ssl_context
    # -------------------
    void mbedtls_ssl_init(mbedtls_ssl_context *ctx)
    int mbedtls_ssl_setup(
        mbedtls_ssl_context *ctx,
        const mbedtls_ssl_config *conf)
    int mbedtls_ssl_session_reset(mbedtls_ssl_context *ctx)
    void mbedtls_ssl_set_bio(
        mbedtls_ssl_context *ssl,
        void *p_bio,
        mbedtls_ssl_send_p f_send,
        mbedtls_ssl_recv_p f_recv,
        mbedtls_ssl_recv_timeout_p f_recv_timeout)

    void mbedtls_ssl_set_timer_cb(
        # DTLS
        mbedtls_ssl_context *ssl,
        void *p_timer,
        mbedtls_ssl_set_timer_t f_set_timer,
        mbedtls_ssl_get_timer_t f_get_timer)
    int mbedtls_ssl_set_client_transport_id(
        # DTLS
        mbedtls_ssl_context *ssl,
        const unsigned char *info,
        size_t ilen)
    int mbedtls_ssl_set_session(
        const mbedtls_ssl_context *ssl,
        mbedtls_ssl_session *session)
    # mbedtls_ssl_set_hs_psk
    int mbedtls_ssl_set_hostname(
        mbedtls_ssl_context *ssl,
        const char *hostname)
    # mbedtls_ssl_set_hs_ecjpake_password
    # mbedtls_ssl_set_hs_own_cert
    # mbedtls_ssl_set_hs_ca_chain
    # mbedtls_ssl_set_hs_authmode
    const char* mbedtls_ssl_get_alpn_protocol(const mbedtls_ssl_context *ctx)
    size_t mbedtls_ssl_get_bytes_avail(const mbedtls_ssl_context *ctx)
    # mbedtls_ssl_get_verify_result
    const char* mbedtls_ssl_get_ciphersuite(const mbedtls_ssl_context *ssl)
    const char* mbedtls_ssl_get_version(const mbedtls_ssl_context *ssl)
    # mbedtls_ssl_get_record_expansion
    size_t mbedtls_ssl_get_max_frag_len(const mbedtls_ssl_context *ssl)
    # const _x509.mbedtls_x509_crt *mbedtls_ssl_get_peer_cert(
    #     const mbedtls_ssl_context *ctx)
    int mbedtls_ssl_get_session(
        const mbedtls_ssl_context *ssl,
        mbedtls_ssl_session *session)
    int mbedtls_ssl_handshake(mbedtls_ssl_context *ctx)
    int mbedtls_ssl_handshake_step(mbedtls_ssl_context *ssl)
    int mbedtls_ssl_renegotiate(mbedtls_ssl_context *ssl)
    int mbedtls_ssl_read(
        mbedtls_ssl_context *ctx,
        unsigned char *buf,
        size_t len)
    int mbedtls_ssl_write(
        mbedtls_ssl_context *ctx,
        const unsigned char *buf,
        size_t len)
    # mbedtls_ssl_send_alert_message
    int mbedtls_ssl_close_notify(mbedtls_ssl_context *ssl)
    void mbedtls_ssl_free(mbedtls_ssl_context *ctx)

    # mbedtls_ssl_session
    # -------------------
    void mbedtls_ssl_session_init(mbedtls_ssl_session *session)
    void mbedtls_ssl_session_free(mbedtls_ssl_session *session)


cdef extern from "mbedtls/ssl_cookie.h" nogil:
    # This provides callbacks for DTLS.

    ctypedef struct mbedtls_ssl_cookie_ctx:
        # mbedtls_md_context_t hmac_ctx
        unsigned long timeout
        # mbedtls_threading_mutex_t mutex

    void mbedtls_ssl_cookie_init(mbedtls_ssl_cookie_ctx *ctx)
    int mbedtls_ssl_cookie_setup(
        mbedtls_ssl_cookie_ctx *ctx,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
    )
    void mbedtls_ssl_cookie_set_timeout(
        mbedtls_ssl_cookie_ctx *ctx,
        unsigned long delay,
    )
    void mbedtls_ssl_cookie_free(mbedtls_ssl_cookie_ctx *ctx)
    mbedtls_ssl_cookie_write_t mbedtls_ssl_cookie_write
    mbedtls_ssl_cookie_check_t mbedtls_ssl_cookie_check


cdef class _DTLSCookie:
    cdef mbedtls_ssl_cookie_ctx _ctx


cdef class _BaseConfiguration:
    cdef mbedtls_ssl_config _ctx
    cdef int *_ciphers
    cdef char **_protos
    # cdef'd because we aim at a non-writable structure.
    cdef _set_validate_certificates(self, validate)
    cdef _set_certificate_chain(self, chain)
    cdef _set_ciphers(self, ciphers)
    cdef _set_inner_protocols(self, protocols)
    cdef _set_lowest_supported_version(self, version)
    cdef _set_highest_supported_version(self, version)
    cdef _set_trust_store(self, object store)
    cdef _set_sni_callback(self, callback)


cdef class TLSConfiguration(_BaseConfiguration):
    pass


cdef class DTLSConfiguration(_BaseConfiguration):
    cdef _DTLSCookie _cookie
    cdef _set_anti_replay(self, mode)
    cdef _set_cookie(self, _DTLSCookie cookie)


cdef class _TLSSession:
    cdef mbedtls_ssl_session _ctx


cdef class _BaseContext:
    cdef mbedtls_ssl_context _ctx
    cdef _BaseConfiguration _conf
    # DTLS only:
    cdef mbedtls_timing_delay_context _timer


cdef class ClientContext(_BaseContext):
    pass


cdef class ServerContext(_BaseContext):
    pass


cdef enum:
    # 16K (tls default)
    TLS_BUFFER_CAPACITY = 16384 + 1024


cdef class TLSWrappedBuffer:
    cdef _rb.RingBuffer _buffer
    cdef _BaseContext _context
    cdef void _as_bio(self)


cdef class TLSWrappedSocket:
    cdef _net.mbedtls_net_context _ctx
    cdef TLSWrappedBuffer _buffer
    cdef _socket
    cdef void _as_bio(self)
