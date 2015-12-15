.DEFAULT_GOAL := debug

release:
	python setup.py build_ext

debug:
	python setup.py build_ext --inplace

test:
	nosetests -v tests

doc:
	cd docs && make html

clean:
	$(RM) mbedtls/*.c mbedtls/*.so
	$(RM) -r build
