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

# Silence error where make expects to be running in a git checkout.
touch "$srcdir/framework/exported.make"

make -C "$srcdir" clean
make -C "$srcdir" -j CFLAGS="-O2" SHARED=ON lib
make -C "$srcdir" -j DESTDIR="$destdir" install
