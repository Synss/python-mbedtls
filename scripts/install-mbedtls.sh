#!/bin/sh
# vim:noet:ts=2:sw=2:tw=79

set -ex

if [ $# -le 1 ]; then
	cat <<-EOF

	usage:
	  $0 SRCDIR [DESTDIR]
	
	Install a mbedtls from the sources in SRCDIR to DESTDIR.

	EOF
	exit 1
else
	srcdir="$1"
	destdir="${2:-/usr/local}"
	case $destdir in
		/*) ;;
		*) destdir="$PWD/$destdir";;
	esac
fi


mkdir -p "$destdir"
cd "$srcdir"
uname -s
if [ "$(uname -s)" = "Linux" ]; then
	sed -i.bk -re "s (^DESTDIR=).* \\1$destdir g" Makefile
else
	sed -i.bk -E "s (^DESTDIR=).* \\1$destdir g" Makefile
fi

[ -d "build" ] && rm -ri build
mkdir build
cd build

CFLAGS="-DMBEDTLS_ARIA_C=ON" \
SHARED="ON" \
make -C .. -j lib
make -C .. -j install
