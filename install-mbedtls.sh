#!/bin/sh
# vim:noet:ts=2:sw=2:tw=79

set -ex

if [ $# -ne 3 ] && [ -n "$2" ]; then
	version="$1"
	case $2 in
		/*) destdir=$2;;
		*) destdir=$PWD/$2;;
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
url="https://tls.mbed.org/download/$name-$version-$license.tgz"
src="$destdir/_src"

mkdir -p "$src"
wget -qO - "$url" | tar xz -C "$src" --strip-components 1

mkdir -p "$destdir"
cd "$src"
cmake . \
	-DCMAKE_INSTALL_PREFIX=$destdir \
	-DENABLE_TESTING=OFF \
	-DUSE_SHARED_MBEDTLS_LIBRARY=ON
make -j4
make install
