#!/bin/sh

LICENSE_MISSING="$(
  grep -L '^# SPDX-License-Identifier: MIT$' "$@"
)"
printf "%s\n" "$LICENSE_MISSING"
test -z "$LICENSE_MISSING"
