#!/bin/sh
# vim:noet:ts=2:sw=2:tw=79

set -ex

if [ $# -ne 3 ] && [ -n "$2" ]; then
	version="$1"
	destdir="$2"
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
src="$PWD/src-$version"
builddir="$PWD/build-$version"

mkdir -p "$src"
wget -qO - "$url" | tar xz -C "$src" --strip-components 1

mkdir -p "$builddir"
mkdir -p "$destdir"
cd "$src"
sed -i.bak -E "s,(DESTDIR=).*,\1$destdir," Makefile
SHARED="yes" make -j4 no_test
make install
