.DEFAULT_GOAL := debug

PYX  = $(wildcard mbedtls/*.pyx)
PYX += $(wildcard mbedtls/cipher/*.pyx)
PYX += $(wildcard mbedtls/pk/*.pyx)

LIBMBEDTLS = $(HOME)/lib/mbedtls-2.5.2

release:
	cython $(PYX)
	python setup.py build_ext

debug:
	cython -a -X linetrace=True $(PYX)
	CFLAGS='-DCYTHON_TRACE=1' python setup.py build_ext --inplace \
		   -L$(LIBMBEDTLS)/lib \
		   -I$(LIBMBEDTLS)/include

test:
	pytest --cov mbedtls tests

html:
	cd docs && make html

clean:
	$(RM) mbedtls/*.c mbedtls/*.so
	$(RM) mbedtls/cipher/*.c mbedtls/cipher/*.so
	$(RM) mbedtls/pk/*.c mbedtls/pk/*.so
	$(RM) -r build
