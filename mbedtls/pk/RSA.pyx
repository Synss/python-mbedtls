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

    cdef _pk.mbedtls_rsa_context* _rsa

    def __init__(self):
        super().__init__(b"RSA")
        self._rsa = _pk.mbedtls_pk_rsa(self._ctx)

    cpdef generate(self, unsigned int key_size=2048, int exponent=65537):
        """Generate an RSA keypair.

        Arguments:
            key_size (unsigned int): size in bits.
            exponent (int): public RSA exponent.

        """
        check_error(_pk.mbedtls_rsa_gen_key(
            self._rsa, &_random.mbedtls_ctr_drbg_random, &__rng._ctx,
            key_size, exponent))

    cpdef _check_public_key(self):
        """Check a public RSA key."""
        return _pk.mbedtls_rsa_check_pubkey(self._rsa) == 0

    cpdef _check_private_key(self):
        """Check a private RSA key."""
        return _pk.mbedtls_rsa_check_privkey(self._rsa) == 0
