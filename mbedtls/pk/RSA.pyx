"""RSA public-key cryptosystem."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Elaborated Networks GmbH"
__license__ = "MIT License"


cimport _pk
import mbedtls.pk as _pk
cimport mbedtls.random as _random
import mbedtls.random as _random
from mbedtls.exceptions import check_error


__all__ = "RSA",


cdef _random.Random __rng = _pk.get_rng()


cdef class RSA(_pk.CipherBase):

    """RSA public-key cryptosystem."""

    def __init__(self):
        super().__init__(b"RSA")

    cpdef bint has_private(self):
        """Return `True` if the key contains a valid private half."""
        return _pk.mbedtls_rsa_check_privkey(_pk.mbedtls_pk_rsa(self._ctx)) == 0

    cpdef bint has_public(self):
        """Return `True` if the key contains a valid public half."""
        return _pk.mbedtls_rsa_check_pubkey(_pk.mbedtls_pk_rsa(self._ctx)) == 0

    cpdef generate(self, unsigned int key_size=2048, int exponent=65537):
        """Generate an RSA keypair.

        Arguments:
            key_size (unsigned int): size in bits.
            exponent (int): public RSA exponent.

        """
        check_error(_pk.mbedtls_rsa_gen_key(
            _pk.mbedtls_pk_rsa(self._ctx), &_random.mbedtls_ctr_drbg_random,
            &__rng._ctx, key_size, exponent))
