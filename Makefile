.DEFAULT_GOAL := debug

PYX  = $(wildcard mbedtls/*.pyx)
PYX += $(wildcard mbedtls/cipher/*.pyx)
PYX += $(wildcard mbedtls/pk/*.pyx)

LIBMBEDTLS = $(HOME)/lib/mbedtls

debug:
	cython -a -X linetrace=True $(PYX)
	CFLAGS='-DCYTHON_TRACE=1' python setup.py build_ext --inplace \
		   -L$(LIBMBEDTLS)/lib \
		   -I$(LIBMBEDTLS)/include

html:
	cd docs && make html

clean:
	$(RM) mbedtls/*.c mbedtls/*.so mbedtls/*.pyc mbedtls/*.html
	$(RM) mbedtls/cipher/*.c mbedtls/cipher/*.so mbedtls/cipher/*.pyc \
		mbedtls/cipher/*.html
	$(RM) mbedtls/pk/*.c mbedtls/pk/*.so mbedtls/pk/*.pyc mbedtls/pk/*.html
	$(RM) -r build dist
