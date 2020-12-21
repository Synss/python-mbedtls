#!/bin/bash

set -ex

function get_abi_tag {
	local python="${1:?}"
	echo $($python -c 'from wheel import bdist_wheel as w; print(w.get_abi_tag())')
}

function build {
	local python="${1:?}"
	$python --version
	$python setup.py bdist_wheel 1> /dev/null
	rm -r .eggs* build*
}

function audit_linux {
	auditwheel repair "${1:?}"
}

function audit_macos {
	delocate-wheel -w wheelhouse -v "${1:?}"
}

function main {
	local python="${1:-python}"
	local system="${2:-linux}"  # "[linux|macos]"

	build $python
	whl=$(ls ./dist/*$(get_abi_tag $python)*.whl)
	ls $whl

	if [ "$system" = "macos" ]; then
		audit_macos $whl
	else
		audit_linux $whl
	fi
}

main "$@"
