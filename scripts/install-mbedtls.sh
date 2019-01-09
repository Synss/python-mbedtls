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
mkdir build
cd build
cmake .. \
	-DCMAKE_INSTALL_PREFIX=$destdir \
	-DENABLE_TESTING=OFF \
	-DUSE_SHARED_MBEDTLS_LIBRARY=ON \
	-DUSE_STATIC_MBEDTLS_LIBRARY=OFF
make -j
make -j install
