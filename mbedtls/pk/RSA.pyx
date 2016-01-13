"""RSA cryptosystem."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Elaborated Networks GmbH"
__license__ = "Apache License 2.0"


cimport _pk
import mbedtls.pk as _pk
cimport mbedtls.random as _random
import mbedtls.random as _random
from mbedtls.exceptions import check_error


__all__ = "RSA",


cdef _random.Random __rng = _pk.get_rng()


cdef class RSA(_pk.CipherBase):

    def __init__(self, *, digestmod):
        super().__init__(b"RSA", digestmod=digestmod)

    cpdef generate(self, unsigned int key_size=1024, int exponent=65537):
        """Generate an RSA keypair.

        Arguments:
            key_size (unsigned int): size in bits.
            exponent (int): public RSA exponent.

        """
        check_error(_pk.mbedtls_rsa_gen_key(
            _pk.mbedtls_pk_rsa(self._ctx),  # Access RSA context.
            &_random.mbedtls_ctr_drbg_random, &__rng._ctx,
            key_size, exponent))
