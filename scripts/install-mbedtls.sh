#!/bin/sh
# vim:noet:ts=2:sw=2:tw=79

set -ex

if [ $# -eq 1 ] || [ $# -eq 2 ]; then
	version="$1"
	destdir="${2:-/usr/local}"
	case $destdir in
		/*) ;;
		*) destdir="$PWD/$destdir";;
	esac
else
	cat <<-EOF

	usage:
	  $0 VERSION DESTDIR
	
	Download and install a local copy mbedtls at VERSION.

	EOF
	exit 1
fi


license="apache"
name="mbedtls"
filename="$name-$version-$license.tgz"
url="https://tls.mbed.org/download/$filename"
src="$destdir/src"

mkdir -p "$src"
curl -O "$url"
tar xzf "$filename" -C "$src" --strip-components 1

mkdir -p "$destdir"
cd "$src"
uname -s
if [ "$(uname -s)" == "Linux" ]; then
	sed -i.bk -re "s (^DESTDIR=).* \1$destdir g" Makefile
else
	sed -i.bk -E "s (^DESTDIR=).* \1$destdir g" Makefile
fi

mkdir build
cd build

CFLAGS="-DMBEDTLS_ARIA_C=ON" \
SHARED="ON" \
make -C .. -j lib
make -C .. -j install
