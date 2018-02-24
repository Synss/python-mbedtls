"""Declaration from `mbedtls/bignum.h`."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2018, Mathias Laurin"
__license__ = "MIT License"


cdef extern from "mbedtls/bignum.h":
    # Multi-precision integer library
    # -------------------------------
    ctypedef enum mbedtls_mpi: pass
    ctypedef enum mbedtls_mpi_sint: pass

    # mbedtls_mpi
    # -----------
    void mbedtls_mpi_init( mbedtls_mpi *X )
    void mbedtls_mpi_free( mbedtls_mpi *X );

    # mbedtls_mpi_grow
    # mbedtls_mpi_shrink
    # mbedtls_mpi_copy
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

    # mbedtls_mpi_shift_l
    # mbedtls_mpi_shift_r
    # mbedtls_mpi_cmp_abs
    # mbedtls_mpi_cmp_mpi
    # mbedtls_mpi_cmp_int
    # mbedtls_mpi_add_abs
    # mbedtls_mpi_sub_abs
    # mbedtls_mpi_add_mpi
    # mbedtls_mpi_sub_mpi
    # mbedtls_mpi_add_int
    # mbedtls_mpi_sub_int
    # mbedtls_mpi_mul_mpi
    # mbedtls_mpi_mul_int
    # mbedtls_mpi_div_mpi
    # mbedtls_mpi_div_int
    # mbedtls_mpi_mod_mpi
    # mbedtls_mpi_mod_int
    # mbedtls_mpi_exp_mod
    # mbedtls_mpi_fill_random
    # mbedtls_mpi_gcd
    # mbedtls_mpi_inv_mod
    # mbedtls_mpi_is_prime
    # mbedtls_mpi_gen_prime


cdef class MPI:
    cdef mbedtls_mpi _ctx
    cdef _len(self)
    cpdef _from_bytes(self, const unsigned char[:] bytes)
