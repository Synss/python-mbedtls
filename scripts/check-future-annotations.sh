#!/bin/sh

ANNOTATIONS_MISSING="$(
  find programs src tests -name '*.py' -o -name '*.pyi' \
  | xargs grep -L '^from __future__ import annotations$'
)"
printf "%s\n" "$ANNOTATIONS_MISSING"
test -z "$ANNOTATIONS_MISSING"
