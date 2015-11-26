# Python wrapper to mbed TLS

`python-mbedtls` is a thin wrapper to ARM's mbed TLS library.

According to the [official mbed TLS website](https://tls.mbed.org):
> mbed TLS (formerly known as PolarSSL) makes it trivially easy for developers
> to include cryptographic and SSL/TLS capabilities in their (embedded)
> products, facilitating this functionality with a minimal coding footprint.

## License

`python-mbedtls` is licensed under the Apache 2.0 license in order to be fully
compatible with mbed TLS.  The Apache 2.0 license enables the use of
`python-mbedtls` in both open source and closed source projects.


## Installation

The wrapper is currently developed and tested on Debian Jessie and targets
Python 3.4.  It probably works with earlier Python releases although this was
not tested.


### mbed TLS

`python-mbedtls` requires the mbed TLS library that can be installed with:

	git clone https://github.com/ARMmbed/mbedtls.git mbedtls.git
	cd mbedtls.git
	SHARED=1 make no_test
	sudo make install


### python-mbedtls

Building `python-mbedtls` requires Cython:

	python3 -m pip install cython

then,

	git clone https://github.com/Synss/python-mbedtls.git python-mbedtls.git
	cd python-mbedtls.git
	python3 setup.py build_ext

and to run the tests:

	python3 -m pip install nose
	nosetests -v tests


## Contribute

`python-mbedtls` is in an early stage of development and contributions in any
form is welcome.  Note, however, that bugs against mbed TLS should be reported
upstream directly.
