"""Declarations from `mbedtls/x509*.h`.

 - CSR: Certificate signing request parsing and writing.
 - CRL: Certificate revocation list parsing.
 - CRT: Certificate parsing and writing.

"""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2018, Mathias Laurin"
__license__ = "MIT License"


cdef extern from "mbedtls/asn1.h" nogil:
    cdef struct mbedtls_asn1_buf:
        int tag
        size_t len
        unsigned char *p
    cdef struct mbedtls_asn1_sequence:
        mbedtls_asn1_buf buf
        mbedtls_asn1_sequence *next
    cdef struct mbedtls_asn1_named_data:
        mbedtls_asn1_buf oid
        mbedtls_asn1_buf val
        mbedtls_asn1_named_data *next
        unsigned char next_merged


cdef extern from "mbedtls/bignum.h" nogil:
    ctypedef struct mbedtls_mpi:
        pass


cdef extern from "mbedtls/md.h" nogil:
    ctypedef enum mbedtls_md_type_t: pass


cdef extern from "mbedtls/pk.h" nogil:
    ctypedef struct mbedtls_pk_context:
        pass


cdef extern from "mbedtls/x509.h" nogil:
    ctypedef mbedtls_asn1_buf mbedtls_x509_buf
    ctypedef mbedtls_asn1_named_data mbedtls_x509_name
    ctypedef mbedtls_asn1_sequence mbedtls_x509_sequence
    int mbedtls_x509_dn_gets(
        char *buf, size_t size, const mbedtls_x509_name *dn)
    cdef struct mbedtls_x509_time:
        int year, mon, day
        int hour, min, sec


cdef extern from "mbedtls/x509_crt.h" nogil:
    cdef struct mbedtls_x509_crt:
        mbedtls_x509_buf raw
        mbedtls_x509_buf tbs
        int version
        mbedtls_x509_buf serial
        mbedtls_x509_buf sig_oid
        # mbedtls_x509_buf issuer_raw
        # mbedtls_x509_buf subject_raw
        mbedtls_x509_name issuer
        mbedtls_x509_name subject
        mbedtls_x509_time valid_from
        mbedtls_x509_time valid_to
        mbedtls_pk_context pk  # public key
        # mbedtls_x509_buf issuer_id
        # mbedtls_x509_buf subject_id
        # mbedtls_x509_buf v3_ext
        mbedtls_x509_sequence subject_alt_names
        # int ext_types
        int ca_istrue  # 1 if this certificate belongs to a CA, 0 otherwise
        int max_pathlen
        unsigned int key_usage
        # mbedtls_x509_sequence ext_key_usage
        # unsigned char ns_cert_type

        mbedtls_x509_buf sig
        mbedtls_md_type_t sig_md
        # mbedtls_pk_type_t sig_pk
        # void *sig_opts
        mbedtls_x509_crt *next

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
    int mbedtls_x509write_crt_set_basic_constraints(
        mbedtls_x509write_cert *ctx,
        int is_ca, int max_pathlen)

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


cdef extern from "mbedtls/x509_csr.h" nogil:
    # Certificate signing request parsing and writing
    # -----------------------------------------------
    cdef struct mbedtls_x509_csr:
        mbedtls_x509_buf raw
        # mbedtls_x509_buf cri
        int version
        # mbedtls_x509_buf subject_raw
        mbedtls_x509_name subject
        mbedtls_pk_context pk
        mbedtls_x509_buf sig_oid
        mbedtls_x509_buf sig
        mbedtls_md_type_t sig_md
        # mbedtls_pk_type_t sig_pk
        # void *sig_opts

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


cdef extern from "mbedtls/x509_crl.h" nogil:
    # Certificate revocation list parsing
    # -----------------------------------
    ctypedef struct mbedtls_x509_crl_entry:
        mbedtls_x509_buf raw
        mbedtls_x509_buf serial
        mbedtls_x509_time revocation_date
        mbedtls_x509_buf entry_ext
        mbedtls_x509_crl_entry *next

    cdef struct mbedtls_x509_crl:
        mbedtls_x509_buf raw
        mbedtls_x509_buf tbs
        int version
        mbedtls_x509_buf sig_oid
        mbedtls_x509_buf issuer_raw
        mbedtls_x509_name issuer
        mbedtls_x509_time this_update
        mbedtls_x509_time next_update
        mbedtls_x509_crl_entry entry
        mbedtls_x509_buf crl_ext
        mbedtls_x509_buf sig_oid2
        mbedtls_x509_buf sig
        mbedtls_md_type_t sig_md
        # mbedtls_pk_type_t sig_pk
        # void *sig_opts
        mbedtls_x509_crl *next

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
    pass


cdef class CRT(Certificate):
    cdef mbedtls_x509_crt _ctx
    cdef set_next(self, CRT crt)
    cdef unset_next(self)
    cdef CRT _next


cdef class _CRTWriter:
    cdef mbedtls_x509write_cert _ctx


cdef class CSR(Certificate):
    cdef mbedtls_x509_csr _ctx


cdef class _CSRWriter:
    cdef mbedtls_x509write_csr _ctx


cdef class CRL(Certificate):
    cdef mbedtls_x509_crl _ctx
    cdef set_next(self, CRL crl)
    cdef unset_next(self)
    cdef CRL _next
