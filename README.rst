=======================================================
Cryptographic library for Python with Mbed TLS back end
=======================================================

.. image::
   https://circleci.com/gh/Synss/python-mbedtls/tree/develop.svg?style=svg
   :target: https://circleci.com/gh/Synss/python-mbedtls/tree/develop

.. image::
   https://coveralls.io/repos/github/Synss/python-mbedtls/badge.svg?branch=develop
   :target: https://coveralls.io/github/Synss/python-mbedtls?branch=develop


`python-mbedtls`_ is a free cryptographic library for Python that uses
`mbed TLS`_ for back end.

   mbed TLS (formerly known as PolarSSL) makes it trivially easy for
   developers to include cryptographic and SSL/TLS capabilities in their
   (embedded) products, facilitating this functionality with a minimal
   coding footprint.

`python-mbedtls` API follows the recommendations from `PEP 452`_: API for
Cryptographic Hash Functions v2.0 and `PEP 272`_ API for Block Encryption
Algorithms v1.0 and can therefore be used as a drop-in replacements to
`PyCrypto`_ or Python's `hashlib`_ and `hmac`_

.. _python-mbedtls: https://synss.github.io/python-mbedtls
.. _mbed TLS: https://tls.mbed.org
.. _PEP 452: https://www.python.org/dev/peps/pep-0452/
.. _PEP 272: https://www.python.org/dev/peps/pep-0272/
.. _PyCrypto: https://www.dlitz.net/software/pycrypto/
.. _hashlib: https://docs.python.org/3.6/library/hashlib.html
.. _hmac: https://docs.python.org/3.6/library/hmac.html

License
=======

`python-mbedtls` is licensed under the MIT License (see LICENSE.txt).  This
enables the use of `python-mbedtls` in both open source and closed source
projects.  The MIT License is compatible with both GPL and Apache 2.0 license
under which mbed TLS is distributed.


Installation
============

The bindings are tested with Python 2.7, 3.4, 3.5, and 3.6.

`mbedtls` is available on Debian.  Install with::

   # apt-get install libmbedtls-dev
   # apt-get install libpython-dev   # for Python 2, or
   # apt-get install libpython3-dev  # for Python 3

and `pyton-mbedtls`::

   $ python -m pip install python-mbedtls

Message digest with `mbedtls.hash`
----------------------------------

The `mbedtls.hash` module provides MD5, SHA-1, SHA-2, and RIPEMD-160 secure
hashes and message digests.  The API follows the recommendations from PEP 452
so that it can be used as a drop-in replacement to e.g. `hashlib` or
`PyCrypto`.

Here are the examples from `hashlib` ported to `python-mbedtls`::

    >>> from mbedtls import hash as hashlib
    >>> m = hashlib.md5()
    >>> m.update(b"Nobody inspects")
    >>> m.update(b" the spammish repetition")
    >>> m.digest()
    b'\xbbd\x9c\x83\xdd\x1e\xa5\xc9\xd9\xde\xc9\xa1\x8d\xf0\xff\xe9'
    >>> m.digest_size
    16
    >>> m.block_size
    64

More condensed::

   >>> hashlib.sha224(b"Nobody inspects the spammish repetition").hexdigest()
   'a4337bc45a8fc544c03f52dc550cd6e1e87021bc896588bd79e901e2'

Using `new()`::

   >>> h = hashlib.new('ripemd160')
   >>> h.update(b"Nobody inspects the spammish repetition")
   >>> h.hexdigest()
   'cc4a5ce1b3df48aec5d22d1f16b894a0b894eccc'


HMAC algorithm with `mbedtls.hmac`
----------------------------------

The `mbedtls.hmac` module computes HMAC.  The API follows the recommendations
from PEP 452 as well.

Example::

   >>> from mbedtls import hmac
   >>> m = hmac.new(b"This is my secret key", digestmod="md5")
   >>> m.update(b"Nobody inspects")
   >>> m.update(b" the spammish repetition")
   >>> m.digest()
   b'\x9d-/rj\\\x98\x80\xb1rG\x87\x0f\xe9\xe4\xeb'

Warning:

   The message is cleared after calculation of the digest.  Only call
   `mbedtls.hmac.Hmac.digest()` or `mbedtls.hmac.Hmac.hexdigest()` once
   per message.


Symmetric cipher with `mbedtls.cipher`
--------------------------------------

The `mbedtls.cipher` module provides symmetric encryption.  The API follows the
recommendations from PEP 272 so that it can be used as a drop-in replacement to
e.g. `PyCrypto`.

mbedtls provides the following algorithms:

- Aes encryption/decryption (128, 192, and 256 bits) in ECB, CBC, CFB128,
  CTR, GCM, or CCM mode;
- Arc4 encryption/decryption;
- Blowfish encryption/decryption in ECB, CBC, CFB64, or CTR mode;
- Camellia encryption/decryption (128, 192, and 256 bits) in ECB, CBC,
  CFB128, CTR, GCM, or CCM mode;
- DES encryption/decryption in ECB, or CBC mode;

Notes:
   - Tagging and padding are not wrapped.
   - The counter in CTR mode cannot be explicitly provided.

Example::

   >>> from mbedtls import cipher
   >>> c = cipher.AES.new(b"My 16-bytes key.", cipher.MODE_CBC, b"CBC needs an IV.")
   >>> enc = c.encrypt(b"This is a super-secret message!")
   >>> enc
   b'*`k6\x98\x97=[\xdf\x7f\x88\x96\xf5\t\x19J7\x93\xb5\xe0~\t\x9e\x968m\xcd\x9c3\x04o\xe6'
   >>> c.decrypt(enc)
   b'This is a super-secret message!'


RSA public key with `mbedtls.pk`
--------------------------------

The `mbedtls.pk` module provides the RSA cryptosystem.  This includes:

- Public-private key generation and key import/export in PEM and DER
  formats;
- Asymmetric encryption and decryption;
- Message signature and verification.

Key generation, the default size is 2048 bits::

   >>> from mbedtls import pk
   >>> rsa = pk.RSA()
   >>> prv = rsa.generate()
   >>> rsa.key_size
   256

Message encryption and decryption::

   >>> enc = rsa.encrypt(b"secret message")
   >>> rsa.decrypt(enc)
   b'secret message'

Message signature and verification::

   >>> sig = rsa.sign(b"Please sign here.")
   >>> rsa.verify(b"Please sign here.", sig)
   True
   >>> rsa.verify(b"Sorry, wrong message.", sig)
   False
   >>> pub = rsa.export_public_key(format="DER")
   >>> other = pk.RSA()
   >>> other.from_buffer(pub)
   >>> other.verify(b"Please sign here.", sig)
   True

Static and ephemeral Elliptic curve Diffie-Hellman
--------------------------------------------------

The `mbedtls.pk` module provides the ECC cryptosystem.  This includes:

- Public-private key generation and key import/export in the PEM and DER
  formats;
- Asymmetric encrypt and decryption;
- Message signature and verification;
- Ephemeral ECDH key exchange.

`get_supported_curves()` returns the list of supported curves.

The API of the ECC class is the same as the API of the RSA class
but ciphering (`encrypt()` and `decrypt()` is not supported by
MBED TLS).

Message signature and verification---elliptic curve digital signature
algorithm (ECDSA)::

   >>> from mbedtls import pk
   >>> ecdsa = pk.ECC()
   >>> prv = ecdsa.generate()
   >>> sig = ecdsa.sign(b"Please sign here.")
   >>> ecdsa.verify(b"Please sign here.", sig)
   True
   >>> ecdsa.verify(b"Sorry, wrong message.", sig)
   False
   >>> pub = ecdsa.export_public_key(format="DER")
   >>> other = pk.ECC()
   >>> other.from_buffer(pub)
   >>> other.verify(b"Please sign here.", sig)
   True

The classes ECDHServer and ECDHClient may be used for ephemeral ECDH.
The key exchange is as follows::

   >>> srv = pk.ECDHServer()
   >>> cli = pk.ECDHClient()

The server generates the ServerKeyExchange encrypted payload and
passes it to the client::

   >>> ske = srv.generate()
   >>> cli.import_SKE(ske)

then the client generates the ClientKeyExchange encrypted payload and
passes it back to the server::

   >>> cke = cli.generate()
   >>> srv.import_CKE(cke)

Now, client and server may generate their shared secret::

   >>> secret = srv.generate_secret()
   >>> cli.generate_secret() == secret
   True
   >>> srv.shared_secret == cli.shared_secret
   True


Diffie-Hellman-Merkle key exchange
----------------------------------

The classes DHServer and DHClient may be used for DH Key exchange.  The
classes have the same API as ECDHServer and ECDHClient, respectively.

The key exchange is as follow::

   >>> from mbedtls import pk
   >>> srv = pk.DHServer(23, 5)
   >>> cli = pk.DHClient(23, 5)

The values 23 and 5 are the prime modulus (P) and the generator (G).

The server generates the ServerKeyExchange payload::

   >>> ske = srv.generate()
   >>> cli.import_SKE(ske)

The payload ends with :math:`G^X mod P` where `X` is the secret value of
the server.

::

   >>> cke = cli.generate()
   >>> srv.import_CKE(cke)

`cke` is :math:`G^Y mod P` (with `Y` the secret value from the client)
returned as its representation in bytes so that it can be readily
transported over the network.

As in ECDH, client and server may now generate their shared secret::

   >>> secret = srv.generate_secret()
   >>> cli.generate_secret() == secret
   True
   >>> srv.shared_secret == cli.shared_secret
   True


X.509 Certificate writing and parsing with `mbedtls.x509`
---------------------------------------------------------

Create new X.509 certificates::

   >>> import datetime as dt
   >>> from pathlib import Path
   >>>
   >>> from mbedtls import hash as hashlib
   >>> from mbedtls.pk import RSA
   >>> from mbedtls.x509 import Certificate, CSR, CRL
   >>>
   >>> now = dt.datetime.utcnow()
   >>> issuer_key = RSA()
   >>> _ = issuer_key.generate()
   >>> subject_key = RSA()
   >>> prv = subject_key.generate()
   >>>
   >>> crt = Certificate.new(
   ...     start=now, end=now + dt.timedelta(days=90),
   ...     issuer="C=NL,O=PolarSSL,CN=PolarSSL Test CA", issuer_key=issuer_key,
   ...     subject=None, subject_key=subject_key,
   ...     md_alg=hashlib.sha1(), serial=None)
   ...
   >>> csr = CSR.new(subject_key, hashlib.sha1(),
   ...               "C=NL,O=PolarSSL,CN=PolarSSL Server 1")
   >>>

Call ``next(crt)`` to obtain the next certificate in a chain.  The
call raises `StopIteration` if there is no further certificate.
