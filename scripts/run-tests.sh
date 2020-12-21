#!/bin/sh

set -ex

echo "Index: $PIP_INDEX_URL"

python="${1:-python}"
$python -m pip install -r requirements/tests.txt
$python -m pip install --only-binary=:all: python-mbedtls
$python -B -m pytest --color=yes
# Skip doctests on 2.7 because of u"" and b"".
[[ $python =~ "27" ]] || $python -B -m doctest README.rst
