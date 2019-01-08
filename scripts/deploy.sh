#!/bin/sh

set -ex

cat << EOF > $HOME/.pypirc
[pypi]
username: $PYPI_USERNAME
password: $PYPI_PASSWORD
EOF

devpi push python-mbedtls==$TRAVIS_TAG pypi:pypi
