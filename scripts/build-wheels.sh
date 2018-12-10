#!/bin/bash

set -ex

function build {
	local rootdir="$1"
	local pydir
	for pydir in $rootdir/*; do
		$pydir/bin/python --version
		$pydir/bin/python setup.py bdist_wheel 1> /dev/null
		rm -r .eggs* build*
	done
	wait
}

function audit_linux {
	local whl
	for whl in dist/*.whl; do
		auditwheel repair $whl
	done
}

function audit_macos {
	local whl
	for whl in dist/*.whl; do
		delocate-wheel -w wheelhouse -v $whl
	done
}

function main {
	local rootdir="${1:-/opt/python}"
	local system="${2:-linux}"  # "[linux|macos]"

	build $rootdir
	if [ "$system" = "macos" ]; then
		audit_macos
	else
		audit_linux
	fi
}

main "$@"
