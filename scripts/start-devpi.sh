#!/bin/bash

set -ex

function usage {
	echo "Usage:\n\t`basename $0`"\
		"[-u USER] [-p PASSWORD] [-x INDEXNAME]"\
		"SERVER:PORT"
	exit 1
}

user="user"
password=""
indexname="dev"

while getopts "u:p:x:" o
do
	case "$o" in
		u) user="$OPTARG" ;;
		p) password="$OPTARG" ;;
		x) indexname="$OPTARG" ;;
		*) usage;;
	esac
done

devpi=${@:OPTIND:1}
[ -z $devpi ] && usage

PIP_INDEX_URL="$devpi/root/pypi/+simple/"

rm -rf "$HOME/.devpi"

devpi-server --start --init

devpi use $devpi
devpi user --create $user password=$password
devpi login $user --password=$password
devpi index --create $indexname bases=root/pypi
devpi use $user/$indexname

echo "Index created: $devpi/$user/$indexname"
