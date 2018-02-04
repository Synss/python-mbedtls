==========================
Python wrapper to mbed TLS
==========================

.. image::
   https://circleci.com/gh/Synss/python-mbedtls/tree/develop.svg?style=svg
   :target: https://circleci.com/gh/Synss/python-mbedtls/tree/develop

.. image::
   https://coveralls.io/repos/github/Synss/python-mbedtls/badge.svg?branch=develop
   :target: https://coveralls.io/github/Synss/python-mbedtls?branch=develop


`python-mbedtls`_ is a thin wrapper to ARM's mbed TLS library.

According to the `official mbed TLS website`_

   mbed TLS (formerly known as PolarSSL) makes it trivially easy for
   developers to include cryptographic and SSL/TLS capabilities in their
   (embedded) products, facilitating this functionality with a minimal
   coding footprint.

.. _python-mbedtls: https://synss.github.io/python-mbedtls
.. _official mbed TLS website: https://tls.mbed.org


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

   # aptitude install libmbedtls-dev

and the wrapper::

   python -m pip install python-mbedtls


Hashing module (`md.h`)
-----------------------

Message digest algorithms
~~~~~~~~~~~~~~~~~~~~~~~~~

The `mbedtls.hash` module provides MD5, SHA-1, SHA-2, and RIPEMD-160 secure
hashes and message digests.  The API follows the recommendations from PEP 452
so that it can be used as a drop-in replacement to e.g. `hashlib` or
`PyCrypto`.

Here are the examples from `hashlib` executed with `python-mbedtls`::

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


HMAC algorithm
~~~~~~~~~~~~~~

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


Symmetric cipher module (`cipher.h`)
------------------------------------

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
   b'*`k6\x98\x97=[\xdf\x7f\x88\x96\xf5\t\x19J7\x93\xb5\xe0~\t\x9e\x968m\xcd\x
   >>> c.decrypt(enc)
   b'This is a super-secret message!'


Public key module (`pk.h`)
--------------------------

The `mbedtls.pk` module provides the RSA cryptosystem.  This includes:

- Public-private key generation and key import/export in PEM and DER
  formats;
- Asymmetric encryption and decryption;
- Message signature and verification.

Key generation, the default size is 2048 bits::

   >>> from mbedtls import pk
   >>> rsa = pk.RSA()
   >>> rsa.has_private()
   False
   >>> rsa.generate()
   >>> rsa.key_size
   256
   >>> rsa.has_private() and rsa.has_public()
   True

Message encryption and decryption::

   >>> enc = rsa.encrypt(b"secret message")
   >>> rsa.decrypt(enc)
   b"secret message"

Message signature and verification::

   >>> sig = rsa.sign(b"Please sign here.")
   >>> rsa.verify(b"Please sign here.", sig)
   True
   >>> rsa.verify(b"Sorry, wrong message.", sig)
   False
   >>> prv, pub = rsa.export(format="DER")
   >>> other = pk.RSA()
   >>> other.import_(pub)
   >>> other.has_private()
   False
   >>> other.verify(b"Please sign here.", sig)
   True
