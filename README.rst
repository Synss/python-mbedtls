.. vim:tw=72

=======================================================
Cryptographic library for Python with Mbed TLS back end
=======================================================

.. image:: https://results.pre-commit.ci/badge/github/Synss/python-mbedtls/master.svg
   :target: https://results.pre-commit.ci/latest/github/Synss/python-mbedtls/master
   :alt: pre-commit.ci status

.. image::
   https://github.com/Synss/python-mbedtls/actions/workflows/main.yml/badge.svg?branch=master
   :target: https://github.com/Synss/python-mbedtls/actions/

.. image::
   https://coveralls.io/repos/github/Synss/python-mbedtls/badge.svg?branch=master
   :target: https://coveralls.io/github/Synss/python-mbedtls?branch=master


`python-mbedtls`_ is a free cryptographic library for Python that uses
`mbed TLS`_ for back end.

   mbed TLS (formerly known as PolarSSL) makes it trivially easy for
   developers to include cryptographic and SSL/TLS capabilities in their
   (embedded) products, facilitating this functionality with a minimal
   coding footprint.

*python-mbedtls* API follows the recommendations from:

* `PEP 272`_ -- API for Block Encryption Algorithms v1.0
* `PEP 452`_ -- API for Cryptographic Hash Functions v2.0
* `PEP 506`_ -- Adding a Secret Module to the Standard Library
* `PEP 543`_ -- A Unified TLS API for Python (`completed and modernized`_)

and therefore plays well with the `cryptographic services`_ from the
Python standard library and many other cryptography libraries as well.

.. _python-mbedtls: https://synss.github.io/python-mbedtls
.. _mbed TLS: https://tls.mbed.org
.. _PEP 272: https://www.python.org/dev/peps/pep-0272/
.. _PEP 452: https://www.python.org/dev/peps/pep-0452/
.. _PEP 506: https://www.python.org/dev/peps/pep-0506/
.. _PEP 543: https://www.python.org/dev/peps/pep-0543/
.. _cryptographic services: https://docs.python.org/3/library/crypto.html
.. _PyCrypto: https://www.dlitz.net/software/pycrypto/
.. _hashlib: https://docs.python.org/3.6/library/hashlib.html
.. _hmac: https://docs.python.org/3.6/library/hmac.html
.. _completed and modernized: https://github.com/Synss/python-mbedtls/blob/master/src/mbedtls/_tlsi.py


License
=======

*python-mbedtls* is licensed under the MIT License (see LICENSE.txt).
This enables the use of *python-mbedtls* in both open source and closed
source projects.  The MIT License is compatible with both GPL and Apache
2.0 license under which mbed TLS is distributed.


API documentation
=================

https://synss.github.io/python-mbedtls/


Installation
============

The bindings are tested with mbedTLS 2.28.6 for Python 3.8,
3.9, 3.10, 3.11, and 3.12 on Linux, macOS, and Windows.

`manylinux`_ wheels are available for 64-bit Linux systems.  Install
with ``pip install python-mbedtls``.

.. _manylinux: https://www.python.org/dev/peps/pep-0513/


Usage and examples
==================

Now, let us see examples using the various parts of the library.


Check which version of mbed TLS is being used by python-mbedtls
---------------------------------------------------------------

The *mbedtls.version* module shows the run-time version
information to mbed TLS.

>>> from mbedtls import version
>>> _ = version.version  # "Mbed TLS 2.28.6"
>>> _ = version.version_info  # (2, 28, 6)


Message digest
--------------

The *mbedtls.hashlib* module supports MD2, MD4, MD5, SHA-1, SHA-2
(in 224, 256, 384, and 512-bits), and RIPEMD-160 secure hashes
and message digests.  Note that MD2 and MD4 are not included
by default and are only present if they are compiled in mbedtls.

Here are the examples from (standard) *hashlib* ported
to *python-mbedtls*:

>>> from mbedtls import hashlib
>>> m = hashlib.md5()
>>> m.update(b"Nobody inspects")
>>> m.update(b" the spammish repetition")
>>> m.digest()
b'\xbbd\x9c\x83\xdd\x1e\xa5\xc9\xd9\xde\xc9\xa1\x8d\xf0\xff\xe9'
>>> m.digest_size
16
>>> m.block_size
64

More condensed:

>>> hashlib.sha224(b"Nobody inspects the spammish repetition").hexdigest()
'a4337bc45a8fc544c03f52dc550cd6e1e87021bc896588bd79e901e2'

Using ``new()``:

>>> h = hashlib.new('ripemd160')
>>> h.update(b"Nobody inspects the spammish repetition")
>>> h.hexdigest()
'cc4a5ce1b3df48aec5d22d1f16b894a0b894eccc'


HMAC algorithm
--------------

The *mbedtls.hmac* module computes HMAC.

Example:

>>> from mbedtls import hmac
>>> m = hmac.new(b"This is my secret key", digestmod="md5")
>>> m.update(b"Nobody inspects")
>>> m.update(b" the spammish repetition")
>>> m.digest()
b'\x9d-/rj\\\x98\x80\xb1rG\x87\x0f\xe9\xe4\xeb'

Warning:

The message is cleared after calculation of the digest.  Only call
``mbedtls.hmac.Hmac.digest()`` or ``mbedtls.hmac.Hmac.hexdigest()``
once per message.


HMAC-based key derivation function (HKDF)
-----------------------------------------

The *mbedtls.hkdf* module exposes extract-and-expand key derivation
functions.  The main function is ``hkdf()`` but ``extract()`` and
``expand()`` may be used as well.

Example:

>>> from mbedtls import hkdf
>>> hkdf.hkdf(
...     b"my secret key",
...     length=42,
...     info=b"my cool app",
...     salt=b"and pepper",
...     digestmod=hmac.sha256
... )
b'v,\xef\x90\xccU\x1d\x1b\xd7\\a\xaf\x92\xac\n\x90\xf9q\xf4)\xcd"\xf7\x1a\x94p\x03.\xa8e\x1e\xfb\x92\xe8l\x0cc\xf8e\rvj'

where *info*, *salt*, and *digestmod* are optional, although providing
(at least) *info* is highly recommended.


Symmetric cipher
----------------

The *mbedtls.cipher* module provides symmetric encryption.  The API
follows the recommendations from PEP 272 so that it can be used as a
drop-in replacement to other libraries.

*python-mbedtls* provides the following algorithms:

- AES encryption/decryption (128, 192, and 256 bits) in ECB, CBC, CFB128,
  CTR, OFB, or XTS mode;
- AES AEAD (128, 192, and 256 bits) in GCM or CCM mode;
- ARC4 encryption/decryption;
- ARIA encryption/decryption (128, 192, and 256 bits) in ECB, CBC,
  CTR, or GCM modes;
- Blowfish encryption/decryption in ECB, CBC, CFB64, or CTR mode;
- Camellia encryption/decryption (128, 192, and 256 bits) in ECB, CBC,
  CFB128, CTR, or GCM mode;
- DES, DES3, and double DES3 encryption/decryption in ECB or CBC mode;
- CHACHA20 and CHACHA20/POLY1305 encryption/decryption.

Example:

>>> from mbedtls import cipher
>>> c = cipher.AES.new(b"My 16-bytes key.", cipher.MODE_CBC, b"CBC needs an IV.")
>>> enc = c.encrypt(b"This is a super-secret message!!")
>>> enc
b"*`k6\x98\x97=[\xdf\x7f\x88\x96\xf5\t\x19J\xf62h\xf4n\xca\xe8\xfe\xf5\xd7X'\xb1\x8c\xc9\x85"
>>> c.decrypt(enc)
b'This is a super-secret message!!'


RSA public key
--------------

The *mbedtls.pk* module provides the RSA cryptosystem.  This includes:

- Public-private key generation and key import/export in PEM and DER
  formats;
- asymmetric encryption and decryption;
- message signature and verification.

Key generation, the default size is 2048 bits:

>>> from mbedtls import pk
>>> rsa = pk.RSA()
>>> prv = rsa.generate()
>>> rsa.key_size
256

Message encryption and decryption:

>>> enc = rsa.encrypt(b"secret message")
>>> rsa.decrypt(enc)
b'secret message'

Message signature and verification:

>>> sig = rsa.sign(b"Please sign here.")
>>> rsa.verify(b"Please sign here.", sig)
True
>>> rsa.verify(b"Sorry, wrong message.", sig)
False
>>> pub = rsa.export_public_key(format="DER")
>>> other = pk.RSA.from_buffer(pub)
>>> other.verify(b"Please sign here.", sig)
True


Static and ephemeral elliptic curve Diffie-Hellman
--------------------------------------------------

The *mbedtls.pk* module provides the ECC cryptosystem.  This includes:

- Public-private key generation and key import/export in the PEM and DER
  formats;
- asymmetric encrypt and decryption;
- message signature and verification;
- ephemeral ECDH key exchange.

``get_supported_curves()`` returns the list of supported curves.

The API of the ECC class is the same as the API of the RSA class
but ciphering (``encrypt()`` and ``decrypt()`` is not supported by
Mbed TLS).

Message signature and verification using elliptic a curve digital
signature algorithm (ECDSA):

>>> from mbedtls import pk
>>> ecdsa = pk.ECC()
>>> prv = ecdsa.generate()
>>> sig = ecdsa.sign(b"Please sign here.")
>>> ecdsa.verify(b"Please sign here.", sig)
True
>>> ecdsa.verify(b"Sorry, wrong message.", sig)
False
>>> pub = ecdsa.export_public_key(format="DER")
>>> other = pk.ECC.from_buffer(pub)
>>> other.verify(b"Please sign here.", sig)
True

The classes ``ECDHServer`` and ``ECDHClient`` may be used for ephemeral
ECDH.  The key exchange is as follows:

>>> ecdh_key = pk.ECC()
>>> ecdh_key.generate()
>>> ecdh_srv = pk.ECDHServer(ecdh_key)
>>> ecdh_cli = pk.ECDHClient(ecdh_key)

The server generates the ServerKeyExchange encrypted payload and
passes it to the client:

>>> ske = ecdh_srv.generate()
>>> ecdh_cli.import_SKE(ske)

then the client generates the ClientKeyExchange encrypted payload and
passes it back to the server:

>>> cke = ecdh_cli.generate()
>>> ecdh_srv.import_CKE(cke)

Now, client and server may generate their shared secret:

>>> secret = ecdh_srv.generate_secret()
>>> ecdh_cli.generate_secret() == secret
True
>>> ecdh_srv.shared_secret == ecdh_cli.shared_secret
True


Diffie-Hellman-Merkle key exchange
----------------------------------

The classes ``DHServer`` and ``DHClient`` may be used for DH Key
exchange.  The classes have the same API as ``ECDHServer``
and ``ECDHClient``, respectively.

The key exchange is as follow:

>>> from mbedtls.mpi import MPI
>>> from mbedtls import pk
>>> dh_srv = pk.DHServer(MPI.prime(128), MPI.prime(96))
>>> dh_cli = pk.DHClient(MPI.prime(128), MPI.prime(96))

The 128-bytes prime and the 96-bytes prime are the modulus ``P``
and the generator ``G``.

The server generates the ServerKeyExchange payload:

>>> ske = dh_srv.generate()
>>> dh_cli.import_SKE(ske)

The payload ends with ``G^X mod P`` where ``X`` is the secret value of
the server.

>>> cke = dh_cli.generate()
>>> dh_srv.import_CKE(cke)

``cke`` is ``G^Y mod P`` (with ``Y`` the secret value from the client)
returned as its representation in bytes so that it can be readily
transported over the network.

As in ECDH, client and server may now generate their shared secret:

>>> secret = dh_srv.generate_secret()
>>> dh_cli.generate_secret() == secret
True
>>> dh_srv.shared_secret == dh_cli.shared_secret
True


X.509 certificate writing and parsing
-------------------------------------

The *mbedtls.x509* module can be used to parse X.509 certificates
or create and verify a certificate chain.

Here, the trusted root is a self-signed CA certificate
``ca0_crt`` signed by ``ca0_key``.

>>> import datetime as dt
>>>
>>> from mbedtls import hashlib
>>> from mbedtls import pk
>>> from mbedtls import x509
>>>
>>> now = dt.datetime.utcnow()
>>> ca0_key = pk.RSA()
>>> _ = ca0_key.generate()
>>> ca0_csr = x509.CSR.new(ca0_key, "CN=Trusted CA", hashlib.sha256())
>>> ca0_crt = x509.CRT.selfsign(
...     ca0_csr, ca0_key,
...     not_before=now, not_after=now + dt.timedelta(days=90),
...     serial_number=0x123456,
...     basic_constraints=x509.BasicConstraints(True, 1))
...

An intermediate then issues a Certificate Singing Request (CSR) that the
root CA signs:

>>> ca1_key = pk.ECC()
>>> _ = ca1_key.generate()
>>> ca1_csr = x509.CSR.new(ca1_key, "CN=Intermediate CA", hashlib.sha256())
>>>
>>> ca1_crt = ca0_crt.sign(
...     ca1_csr, ca0_key, now, now + dt.timedelta(days=90), 0x123456,
...     basic_constraints=x509.BasicConstraints(ca=True, max_path_length=3))
...

And finally, the intermediate CA signs a certificate for the
End Entity on the basis of a new CSR:

>>> ee0_key = pk.ECC()
>>> _ = ee0_key.generate()
>>> ee0_csr = x509.CSR.new(ee0_key, "CN=End Entity", hashlib.sha256())
>>>
>>> ee0_crt = ca1_crt.sign(
...     ee0_csr, ca1_key, now, now + dt.timedelta(days=90), 0x987654)
...

The emitting certificate can be used to verify the next certificate in
the chain:

>>> ca1_crt.verify(ee0_crt)
True
>>> ca0_crt.verify(ca1_crt)
True

Note, however, that this verification is only one step in a private key
infrastructure and does not take CRLs, path length, etc. into account.


TLS and DTLS client and server
------------------------------

The *mbedtls.tls* module provides TLS clients and servers.  The API
follows the recommendations of `PEP 543`_.  Note, however, that the
Python standard SSL library does not follow the PEP so that this
library may not be a drop-in replacement.

.. _PEP 543: https://www.python.org/dev/peps/pep-0543/

Connectionless DTLS is supported as well.

See examples in the `programs/`_ directory of the repository
and `tests/test_tls.py`_.

.. _programs/: https://github.com/Synss/python-mbedtls/tree/master/programs
.. _tests/test_tls.py: https://github.com/Synss/python-mbedtls/blob/master/tests/test_tls.py
