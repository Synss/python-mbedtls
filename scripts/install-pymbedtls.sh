#!/bin/sh
# vim:noet:ts=2:sw=2:tw=79

set -e

if [ $# -eq 0 ] || [ $# -gt 2 ]; then
	cat <<- EOF

	usage:
	  $0 LIBDIR [ VERSION ]

	Install python-mbedtls locally, using mbedtls from LIBDIR

	The script requires 'delocate' on MacOS or 'auditwheel' on Linux.

	EOF
	exit 1
fi

if [ -n "$(command -v delocate-wheel)" ]; then
	fixlib="delocate-wheel -v"
elif [ -n "$(command -v auditwheel)" ]; then
	fixlib="auditwheel repair"
else
	echo "Missing requirement."
	exit 1
fi

libdir="$1"
version="${2:-*}"

python="cp$(python --version 2>&1 | perl -ne '/^Python\ (\d+)\.(\d+)/ && print "$1$2"')"
wheel="python_mbedtls-$version-$python-$python"'*.whl'

C_INCLUDE_PATH="$libdir/include"
LIBRARY_PATH="$libdir/lib"
LD_LIBRARY_PATH=$LIBRARY_PATH
DYLD_LIBRARY_PATH=$LIBRARY_PATH

export C_INCLUDE_PATH
export LIBRARY_PATH
export LD_LIBRARY_PATH
export DYLD_LIBRARY_PATH

python setup.py bdist_wheel || exit 1
$fixlib dist/$wheel || exit 1
pip install --upgrade --force-reinstall dist/$wheel || exit 1
