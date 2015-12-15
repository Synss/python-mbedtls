==========================
Python wrapper to mbed TLS
==========================

`python-mbedtls` is a thin wrapper to ARM's mbed TLS library.

According to the `official mbed TLS website`_

   mbed TLS (formerly known as PolarSSL) makes it trivially easy for
   developers to include cryptographic and SSL/TLS capabilities in their
   (embedded) products, facilitating this functionality with a minimal
   coding footprint.

.. _official mbed TLS website: https://tls.mbed.org

License
-------

`python-mbedtls` is licensed under the Apache 2.0 license in order to be fully
compatible with mbed TLS.  The Apache 2.0 license enables the use of
`python-mbedtls` in both open source and closed source projects.


Installation
------------

The wrapper is currently developed and tested on Debian Jessie and targets
Python 3.4.  It probably works with earlier Python releases although this was
not tested.


mbed TLS
~~~~~~~~

`python-mbedtls` requires the mbed TLS library that can be installed
with::

	git clone https://github.com/ARMmbed/mbedtls.git mbedtls.git
	cd mbedtls.git
	SHARED=1 make no_test
	sudo make install


python-mbedtls
~~~~~~~~~~~~~~

Building `python-mbedtls` requires Cython::

	python3 -m pip install cython

then,

::

	git clone https://github.com/Synss/python-mbedtls.git python-mbedtls.git
	cd python-mbedtls.git
	python3 setup.py build_ext

The unit tests further require `nose` and `pyCrypto`::

	python3 -m pip install nose pycrypto
	nosetests -v tests


Ciphers (`cipher.h`)
~~~~~~~~~~~~~~~~~~~~

`cipher.h` is wrapped, which provides:

- Aes encryption/decryption (128, 192, and 256 bits) in ECB, CBC, CFB128,
  CTR, GCM, or CCM mode;
- Arc4 encryption/decryption;
- Blowfish encryption/decryption in ECB, CBC, CFB64, or CTR mode;
- Camellia encryption/decryption (128, 192, and 256 bits) in ECB, CBC,
  CFB128, CTR, GCM, or CCM mode;
- DES encryption/decryption in ECB, or CBC mode;

Notes:
   Tagging and padding are not wrapped.


API documentation
-----------------

The Sphinx-generated API documentation is available on this `website`_.

.. _website: https://synss.github.io/python-mbedtls


Contribution
------------

`python-mbedtls` is in an early stage of development and contributions
in any form is welcome.  Note, however, that bugs against mbed TLS
should be reported upstream directly.
