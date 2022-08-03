#!/bin/sh

LICENSE_MISSING="$(
  find programs src tests -name '*.py' -o -name '*.pyi' -o -name '*.pyx' -o -name '*.pxd' \
  | xargs grep -L '^# SPDX-License-Identifier: MIT$'
)"
printf "%s\n" "$LICENSE_MISSING"
test -z "$LICENSE_MISSING"
