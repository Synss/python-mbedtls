"""Declaration from `mbedtls/bignum.h`."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2018, Mathias Laurin"
__license__ = "MIT License"


cdef extern from "mbedtls/bignum.h" nogil:
    int MBEDTLS_MPI_MAX_SIZE

    # Multi-precision integer library
    # -------------------------------
    ctypedef struct mbedtls_mpi:
        pass

    ctypedef enum mbedtls_mpi_sint:
        pass

    # mbedtls_mpi
    # -----------
    void mbedtls_mpi_init( mbedtls_mpi *X )
    void mbedtls_mpi_free( mbedtls_mpi *X );

    # mbedtls_mpi_grow
    # mbedtls_mpi_shrink

    int mbedtls_mpi_copy(mbedtls_mpi *X, const mbedtls_mpi *Y)

    # mbedtls_mpi_swap
    # mbedtls_mpi_safe_cond_assign
    # mbedtls_mpi_safe_cond_swap
    # mbedtls_mpi_lset  // limited to 64-bits
    # mbedtls_mpi_get_bit
    # mbedtls_mpi_set_bit
    # mbedtls_mpi_lsb

    size_t mbedtls_mpi_bitlen(const mbedtls_mpi *X)
    size_t mbedtls_mpi_size(const mbedtls_mpi *X)

    # mbedtls_mpi_read_string
    # mbedtls_mpi_write_string
    # mbedtls_mpi_read_file
    # mbedtls_mpi_write_file

    int mbedtls_mpi_read_binary(
        mbedtls_mpi *X,
        const unsigned char *buf,
        size_t buflen)
    int mbedtls_mpi_write_binary(
        mbedtls_mpi *X,
        unsigned char *buf,
        size_t buflen)

    int mbedtls_mpi_shift_l(
        mbedtls_mpi *X,
        size_t count)
    int mbedtls_mpi_shift_r(
        mbedtls_mpi *X,
        size_t count)
    # mbedtls_mpi_cmp_abs
    int mbedtls_mpi_cmp_mpi(
        const mbedtls_mpi *X,
        const mbedtls_mpi *Y)
    # mbedtls_mpi_cmp_int
    # mbedtls_mpi_add_abs
    # mbedtls_mpi_sub_abs
    int mbedtls_mpi_add_mpi(
        mbedtls_mpi *X,
        const mbedtls_mpi *A,
        const mbedtls_mpi *B)
    int mbedtls_mpi_sub_mpi(
        mbedtls_mpi *X,
        const mbedtls_mpi *A,
        const mbedtls_mpi *B)
    # mbedtls_mpi_add_int
    # mbedtls_mpi_sub_int
    int mbedtls_mpi_mul_mpi(
        mbedtls_mpi *X,
        const mbedtls_mpi *A,
        const mbedtls_mpi *B)
    # mbedtls_mpi_mul_int
    int mbedtls_mpi_div_mpi(
        mbedtls_mpi *Q,
        mbedtls_mpi *R,
        const mbedtls_mpi *A,
        const mbedtls_mpi *B)
    # mbedtls_mpi_div_int
    int mbedtls_mpi_mod_mpi(
        mbedtls_mpi *X,
        const mbedtls_mpi *A,
        const mbedtls_mpi *B)
    # mbedtls_mpi_mod_int
    int mbedtls_mpi_exp_mod(
        mbedtls_mpi *X,
        const mbedtls_mpi *A,
        const mbedtls_mpi *E,
        const mbedtls_mpi *N,
        mbedtls_mpi *_RR)
    int mbedtls_mpi_fill_random(
        mbedtls_mpi *X, size_t size,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
    # mbedtls_mpi_gcd
    # mbedtls_mpi_inv_mod
    int mbedtls_mpi_is_prime(
        mbedtls_mpi *X,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
    int mbedtls_mpi_gen_prime(
        mbedtls_mpi *X, size_t size, int dh_flag,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )


cdef class MPI:
    cdef mbedtls_mpi _ctx
    cdef size_t _len(self)
    cpdef _read_bytes(self, const unsigned char[:] data)


cdef inline from_mpi(mbedtls_mpi *c_mpi):
    new_mpi = MPI()
    mbedtls_mpi_copy(&new_mpi._ctx, c_mpi)
    return new_mpi
