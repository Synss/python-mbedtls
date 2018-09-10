.DEFAULT_GOAL := debug

PYX  = $(wildcard mbedtls/*.pyx)
PYX += $(wildcard mbedtls/cipher/*.pyx)
PYX += $(wildcard mbedtls/pk/*.pyx)

LIBMBEDTLS = $(HOME)/lib/mbedtls

clean:
	$(RM) mbedtls/*.c mbedtls/*.so mbedtls/*.pyc mbedtls/*.html
	$(RM) mbedtls/cipher/*.c mbedtls/cipher/*.so mbedtls/cipher/*.pyc \
		mbedtls/cipher/*.html
	$(RM) mbedtls/pk/*.c mbedtls/pk/*.so mbedtls/pk/*.pyc mbedtls/pk/*.html
	$(RM) -r build* dist*

debug: clean
	python setup.py build_ext \
				 --inplace \
				 -I$(LIBMBEDTLS)/include \
				 -L$(LIBMBEDTLS)/lib

cov: clean
	python setup.py build_ext \
				 --inplace \
				 -I$(LIBMBEDTLS)/include \
				 -L$(LIBMBEDTLS)/lib \
				 --with-coverage
	python -m coverage run -m pytest tests
	python -m coverage report

html:
	cd docs && make html
