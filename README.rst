=======================================================
Cryptographic library for Python with Mbed TLS back end
=======================================================

.. image::
   https://circleci.com/gh/Synss/python-mbedtls/tree/develop.svg?style=svg
   :target: https://circleci.com/gh/Synss/python-mbedtls/tree/develop

.. image::
   https://travis-ci.org/Synss/python-mbedtls.svg?branch=develop
   :target: https://travis-ci.org/Synss/python-mbedtls

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

The bindings are tested with Python 2.7, 3.4, 3.5, 3.6, and 3.7 on Linux
and macOS.

Manylinux wheels are available for 64-bit Linux systems.  Install
with ``pip install python-mbedtls``.

In other cases, or to bind to a different version of mbed TLS,
clone the `python-mbedtls` repository, install mbed TLS, and install
`python-mbedtls` with::

  $ git clone https://github.com/Synss/python-mbedtls.git python-mbedtls.git
  $ cd python-mbedtls.git
  $ sudo ./scripts/install-mbedtls.sh 2.7.8
  $ python -m pip install python-mbedtls

where 2.7.8 is the version of mbed TLS that will be installed.

`install-mbedtl.sh` is a POSIX shell script and requires `curl`, `tar`,
and `cmake`.

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
   >>> other = pk.RSA.from_buffer(pub)
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
   >>> other = pk.ECC.from_buffer(pub)
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

   >>> from mbedtls.mpi import MPI
   >>> from mbedtls import pk
   >>> srv = pk.DHServer(MPI.prime(128), MPI.prime(96))
   >>> cli = pk.DHClient(MPI.prime(128), MPI.prime(96))

The values 23 and 5 are the prime modulus (P) and the generator (G).

The server generates the ServerKeyExchange payload::

   >>> ske = srv.generate()
   >>> cli.import_SKE(ske)

The payload ends with `G^X mod P` where `X` is the secret value of
the server.

::

   >>> cke = cli.generate()
   >>> srv.import_CKE(cke)

`cke` is `G^Y mod P` (with `Y` the secret value from the client)
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

The x509 module can be used to parse X.509 certificates or create
and verify a certificate chain.

Here, the trusted root is a self-signed CA certificate
`ca0_crt` signed by `ca0_key`::

   >>> import datetime as dt
   >>>
   >>> from mbedtls import hash as hashlib
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
root CA signs::

   >>> ca1_key = pk.ECC()
   >>> _ = ca1_key.generate()
   >>> ca1_csr = x509.CSR.new(ca1_key, "CN=Intermediate CA", hashlib.sha256())
   >>>
   >>> ca1_crt = ca0_crt.sign(
   ...     ca1_csr, ca0_key, now, now + dt.timedelta(days=90), 0x123456, 
   ...     basic_constraints=x509.BasicConstraints(ca=True, max_path_length=3))
   ...

And finally, the intermediate CA signs a certificate for the
End Entity on the basis of a new CSR::

   >>> ee0_key = pk.ECC()
   >>> _ = ee0_key.generate()
   >>> ee0_csr = x509.CSR.new(ee0_key, "CN=End Entity", hashlib.sha256())
   >>>
   >>> ee0_crt = ca1_crt.sign(
   ...     ee0_csr, ca1_key, now, now + dt.timedelta(days=90), 0x987654)
   ...

The emitting certificate can be used to verify the next certificate in
the chain::

   >>> ca1_crt.verify(ee0_crt)
   True
   >>> ca0_crt.verify(ca1_crt)
   True

Note, however, that this verification is only one step in a private key
infrastructure and does not take CRLs, path length, etc. into account.


TLS client and server
---------------------

The `mbedtls.tls` module provides TLS clients and servers.  The API
follows the recommendations of `PEP 543`_.  Note, however, that the
Python standard SSL library does not follow the PEP so that this
library may not be a drop-in replacement.  Also, SSL 3 is not
yet supported.

.. _PEP 543: https://www.python.org/dev/peps/pep-0543/

Here are some simple HTTP messages to pass from the client to the
server and back.

>>> get_request = "\r\n".join((
...     "GET / HTTP/1.0",
...     "",
...     "")).encode("ascii")
...
>>> http_response = "\r\n".join((
...     "HTTP/1.0 200 OK",
...     "Content-Type: text/html",
...     "",
...     "<h2>Test Server</h2>",
...     "<p>Successful connection.</p>",
...     "")).encode("ascii")
...
>>> http_error = "\r\n".join((
...     "HTTP/1.0 400 Bad Request",
...     "",
...     ""))
...

For this example, the trust store just consists in the root certificate
`ca0_crt` from the previous section.

>>> from mbedtls import tls
>>> trust_store = tls.TrustStore()
>>> trust_store.add(ca0_crt)

The next step is to configure the TLS contexts for server and client.

>>> srv_ctx = tls.ServerContext(tls.TLSConfiguration(
...     trust_store=trust_store,
...     certificate_chain=([ee0_crt, ca1_crt], ee0_key),
...     validate_certificates=False,
... ))
...
>>> cli_ctx = tls.ClientContext(tls.TLSConfiguration(
...     trust_store=trust_store,
...     validate_certificates=True,
... ))
...

The contexts are used to wrap TCP sockets.

>>> import socket
>>> srv = srv_ctx.wrap_socket(
...     socket.socket(socket.AF_INET, socket.SOCK_STREAM))
...

>>> try:
...     from contextlib import suppress
... except ImportError:
...     # For Python 2.
...     from contextlib2 import suppress
>>> def block(callback, *args, **kwargs):
...     while True:
...         with suppress(tls.WantReadError, tls.WantWriteError):
...             return callback(*args, **kwargs)
...

The server starts in its own process in this example
because `accept()` is blocking.

>>> def server_main_loop(sock):
...     conn, addr = sock.accept()
...     block(conn.do_handshake)
...     data = conn.recv(1024)
...     if data == get_request:
...         conn.sendall(http_response)
...     else:
...         conn.sendall(http_error)
...

We only scan for free ports to `bind()` to in order to
paralelize the tests.  This should not be needed.

>>> import multiprocessing as mp
>>> for port in range(8888, 8888 + 20):
...     try:
...         srv.bind(("localhost", port))
...     except OSError:
...         pass
...     else:
...         break
... else:
...     raise OSError("No free port found")
...
>>> srv.listen(1)
>>> runner = mp.Process(target=server_main_loop, args=(srv, ))
>>> runner.start()

Finally, a client queries the server with the `get_request`:

>>> cli = cli_ctx.wrap_socket(
...     socket.socket(socket.AF_INET, socket.SOCK_STREAM),
...     server_hostname=None,
... )
...
>>> cli.connect(("localhost", port))
>>> block(cli.do_handshake)
>>> cli.send(get_request)
18
>>> response = block(cli.recv, 1024)
>>> print(response.decode("ascii").replace("\r\n", "\n"))
HTTP/1.0 200 OK
Content-Type: text/html
<BLANKLINE>
<h2>Test Server</h2>
<p>Successful connection.</p>
<BLANKLINE>

The last step is to stop the extra process and close the sockets.

>>> cli.close()
>>> runner.join(1.0)
>>> srv.close()
