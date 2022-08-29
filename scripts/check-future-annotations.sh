#!/bin/sh

ANNOTATIONS_MISSING="$(
  grep -L '^from __future__ import annotations$' "$@"
)"
printf "%s\n" "$ANNOTATIONS_MISSING"
test -z "$ANNOTATIONS_MISSING"
