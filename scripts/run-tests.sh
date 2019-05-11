#!/bin/sh

set -ex

echo "Index: $PIP_INDEX_URL"

for pydir in /opt/python/*; do
	$pydir/bin/python -m pip install -r requirements/tests.txt
	$pydir/bin/python -m pip install \
		--only-binary=:all: \
		python-mbedtls
	$pydir/bin/python -B -m pytest
done

/opt/python/*36*/bin/python -B -m doctest README.rst
