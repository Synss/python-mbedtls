#!/bin/sh
# vim:noet:ts=2:sw=2:tw=79

set -ex

if [ $# -eq 2 ]; then
	version="$1"
	destdir="$2"
	case $destdir in
		/*) ;;
		*) destdir="$PWD/$destdir";;
	esac
else
	cat <<-EOF

	usage:
	  $0 VERSION DESTDIR

	Download a local copy mbedtls at VERSION.

	EOF
	exit 1
fi


name="mbedtls"
filename="$name-$version.tar.gz"
url="https://github.com/ARMmbed/mbedtls/archive/$filename"

mkdir -p "$destdir"
curl -LO "$url"
tar xzf "$filename" -C "$destdir" --strip-components 1
