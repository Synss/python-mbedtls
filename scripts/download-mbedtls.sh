#!/bin/sh
# vim:noet:ts=2:sw=2:tw=79

set -ex

if [ $# -eq 1 ] || [ $# -eq 2 ]; then
	version="$1"
	destdir="${2:-/usr/local/src}"
	case $destdir in
		/*) ;;
		*) destdir="$PWD/$destdir";;
	esac
else
	cat <<-EOF

	usage:
	  $0 VERSION [DESTDIR]

	Download a local copy mbedtls at VERSION.

	EOF
	exit 1
fi


license="apache"
name="mbedtls"
filename="$name-$version-$license.tgz"
url="https://tls.mbed.org/download/$filename"

mkdir -p "$destdir"
curl -O "$url"
tar xzf "$filename" -C "$destdir" --strip-components 1
