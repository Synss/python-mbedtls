#!/bin/sh
# vim:noet:ts=2:sw=2:tw=79

set -ex

if [ $# -eq 1 ] || [ $# -eq 2 ]; then
	srcdir="$1"
	destdir="${2:-/usr/local}"
	case $destdir in
		/*) ;;
		*) destdir="$PWD/$destdir";;
	esac
else
	cat <<-EOF

	usage:
	  $0 SRCDIR [DESTDIR]

	Install a mbedtls from the sources in SRCDIR to DESTDIR.

	EOF
	exit 1
fi

cd "$srcdir"
perl -p -i -e "s|(^DESTDIR=).+$|\1$destdir|g" Makefile
make clean
CFLAGS="-DMBEDTLS_ARIA_C=ON" \
	SHARED="ON" \
	make -j lib
DESTDIR=$destir \
	make -j install
