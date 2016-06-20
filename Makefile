.DEFAULT_GOAL := debug

PYX  = $(wildcard mbedtls/*.pyx)
PYX += $(wildcard mbedtls/cipher/*.pyx)
PYX += $(wildcard mbedtls/pk/*.pyx)

release:
	cython $(PYX)
	python setup.py build_ext

debug:
	cython -a -X linetrace=True $(PYX)
	CFLAGS='-DCYTHON_TRACE=1' python setup.py build_ext --inplace

test:
	nosetests -v --with-coverage --cover-package=mbedtls

html:
	cd docs && make html

clean:
	$(RM) mbedtls/*.c mbedtls/*.so
	$(RM) mbedtls/cipher/*.c mbedtls/cipher/*.so
	$(RM) mbedtls/pk/*.c mbedtls/pk/*.so
	$(RM) -r build
