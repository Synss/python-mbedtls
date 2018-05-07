"""Declarations from `mbedtls/x509*.h`.

 - CSR: Certificate signing request parsing and writing.
 - CRL: Certificate revocation list parsing.
 - CRT: Certificate parsing and writing.

"""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2018, Mathias Laurin"
__license__ = "MIT License"


cdef extern from "mbedtls/asn1.h":
    cdef struct mbedtls_asn1_buf:
        int tag
        size_t len
        unsigned char *p


cdef extern from "mbedtls/bignum.h":
    ctypedef struct mbedtls_mpi:
        pass


cdef extern from "mbedtls/md.h":
    ctypedef enum mbedtls_md_type_t: pass


cdef extern from "mbedtls/pk.h":
    ctypedef struct mbedtls_pk_context:
        pass


cdef extern from "mbedtls/x509.h":
    ctypedef mbedtls_asn1_buf mbedtls_x509_buf


cdef extern from "mbedtls/x509_crt.h":
    cdef struct mbedtls_x509_crt:
        mbedtls_x509_buf raw
        mbedtls_x509_crt *next
        int version

    ctypedef struct mbedtls_x509_crt_profile:
        pass

    ctypedef struct mbedtls_x509write_cert:
        pass

    # mbedtls_x509_crt
    # ----------------
    int mbedtls_x509_crt_parse_der(
        mbedtls_x509_crt *chain,
        const unsigned char *buf,
        size_t buflen)
    int mbedtls_x509_crt_parse(
        mbedtls_x509_crt *chain,
        const unsigned char *buf,
        size_t buflen)
    int mbedtls_x509_crt_parse_file(
        mbedtls_x509_crt *chain,
        const char *path)

    # mbedtls_x509_crt_parse_path

    int mbedtls_x509_crt_info(
        char *buf,
        size_t size,
        const char* prefix,
        const mbedtls_x509_crt *crt)

    # mbedtls_x509_crt_verify_info
    # mbedtls_x509_crt_verify
    # mbedtls_x509_crt_verify_with_profile
    # mbedtls_x509_crt_check_key_usage
    # mbedtls_x509_crt_check_extended_key_usage

    int mbedtls_x509_crt_is_revoked(
        const mbedtls_x509_crt *crt,
        const mbedtls_x509_crl *crl)

    void mbedtls_x509_crt_init(mbedtls_x509_crt *crt)
    void mbedtls_x509_crt_free(mbedtls_x509_crt *crt)

    # mbedtls_x509write_cert
    # ----------------------

    void mbedtls_x509write_crt_init(mbedtls_x509write_cert *ctx)
    void mbedtls_x509write_crt_set_version(
        mbedtls_x509write_cert *ctx,
        int version)
    int mbedtls_x509write_crt_set_serial(
        mbedtls_x509write_cert *ctx,
        mbedtls_mpi *serial)

    int mbedtls_x509write_crt_set_validity(
        mbedtls_x509write_cert *ctx,
        const char *not_before,
        const char *not_after)
    int mbedtls_x509write_crt_set_issuer_name(
        mbedtls_x509write_cert *ctx,
        const char *issuer_name)
    int mbedtls_x509write_crt_set_subject_name(
        mbedtls_x509write_cert *ctx,
        const char *subject_name)
    void mbedtls_x509write_crt_set_subject_key(
        mbedtls_x509write_cert *ctx,
        mbedtls_pk_context *key)
    void mbedtls_x509write_crt_set_issuer_key(
        mbedtls_x509write_cert *ctx,
        mbedtls_pk_context *key)
    void mbedtls_x509write_crt_set_md_alg(
        mbedtls_x509write_cert *ctx,
        mbedtls_md_type_t md_alg)

    # mbedtls_x509write_crt_set_extension
    # mbedtls_x509write_crt_set_basic_constraints

    int mbedtls_x509write_crt_set_subject_key_identifier(
        mbedtls_x509write_cert *ctx)
    int mbedtls_x509write_crt_set_authority_key_identifier(
        mbedtls_x509write_cert *ctx)

    # mbedtls_x509write_crt_set_key_usage
    # mbedtls_x509write_crt_set_ns_cert_type

    void mbedtls_x509write_crt_free(mbedtls_x509write_cert *ctx)

    int mbedtls_x509write_crt_der(
        mbedtls_x509write_cert *ctx,
        unsigned char *buf, size_t size,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng)
    int mbedtls_x509write_crt_pem(
        mbedtls_x509write_cert *ctx,
        unsigned char *buf, size_t size,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng)


cdef extern from "mbedtls/x509_csr.h":
    # Certificate signing request parsing and writing
    # -----------------------------------------------
    cdef struct mbedtls_x509_csr:
        mbedtls_x509_buf raw

    ctypedef struct mbedtls_x509write_csr:
        pass

    # mbedtls_x509_csr
    # ----------------
    int mbedtls_x509_csr_parse_der(
        mbedtls_x509_csr *csr,
        const unsigned char *buf,
        size_t buflen)
    int mbedtls_x509_csr_parse(
        mbedtls_x509_csr *csr,
        const unsigned char *buf,
        size_t buflen)
    int mbedtls_x509_csr_parse_file(
        mbedtls_x509_csr *csr,
        const char *path)
    int mbedtls_x509_csr_info(
        char *buf,
        size_t size,
        const char* prefix,
        const mbedtls_x509_csr *csr)
    void mbedtls_x509_csr_init(mbedtls_x509_csr *csr)
    void mbedtls_x509_csr_free(mbedtls_x509_csr *csr)

    # mbedtls_x509write_csr
    # ---------------------
    void mbedtls_x509write_csr_init(mbedtls_x509write_csr *ctx)

    int mbedtls_x509write_csr_set_subject_name(
        mbedtls_x509write_csr *ctx,
        const char *subject_name)
    void mbedtls_x509write_csr_set_key(
        mbedtls_x509write_csr *ctx,
        mbedtls_pk_context *key)
    void mbedtls_x509write_csr_set_md_alg(
        mbedtls_x509write_csr *ctx,
        mbedtls_md_type_t md_alg)

    # mbedtls_x509write_csr_set_key_usage
    # mbedtls_x509write_csr_set_ns_cert_type
    # mbedtls_x509write_csr_set_extension

    void mbedtls_x509write_csr_free(mbedtls_x509write_csr *ctx)

    int mbedtls_x509write_csr_der(
        mbedtls_x509write_csr *ctx,
        unsigned char *buf, size_t size,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng)
    int mbedtls_x509write_csr_pem(
        mbedtls_x509write_csr *ctx,
        unsigned char *buf, size_t size,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng)


cdef extern from "mbedtls/x509_crl.h":
    # Certificate revocation list parsing
    # -----------------------------------
    ctypedef struct mbedtls_x509_crl_entry:
        pass

    cdef struct mbedtls_x509_crl:
        mbedtls_x509_buf raw
        mbedtls_x509_crl *next
        int version

    # mbedtls_x509_crl
    # ----------------
    int mbedtls_x509_crl_parse_der(
        mbedtls_x509_crl *chain,
        const unsigned char *buf,
        size_t buflen)
    int mbedtls_x509_crl_parse(
        mbedtls_x509_crl *chain,
        const unsigned char *buf,
        size_t buflen)
    int mbedtls_x509_crl_parse_file(
        mbedtls_x509_crl *chain,
        const char *path)
    int mbedtls_x509_crl_info(
        char *buf,
        size_t size,
        const char *prefix,
        const mbedtls_x509_crl *crl)
    void mbedtls_x509_crl_init(mbedtls_x509_crl *crl)
    void mbedtls_x509_crl_free(mbedtls_x509_crl *crl)


cdef class Certificate:
    cdef mbedtls_x509_crt _ctx
    cpdef _from_buffer(cls, const unsigned char[:] buffer)


cdef class _CertificateWriter:
    cdef mbedtls_x509write_cert _ctx


cdef class CSR:
    cdef mbedtls_x509_csr _ctx
    cpdef _from_buffer(cls, const unsigned char[:] buffer)


cdef class _CSRWriter:
    cdef mbedtls_x509write_csr _ctx


cdef class CRL:
    cdef mbedtls_x509_crl _ctx
    cpdef _from_buffer(cls, const unsigned char[:] buffer)
