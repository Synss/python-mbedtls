#!/bin/sh

set -e

die() {
    printf "%s\n" "$*"
    exit 1
}

command -v python -m pip-compile 1> /dev/null || die "pip-tools is missing"

for input in setup.py requirements/*.in; do
    pip-compile --upgrade --resolver=backtracking --no-annotate "$input"
done
