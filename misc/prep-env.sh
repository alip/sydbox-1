#!/bin/sh

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"
if [[ -n "$ROOT" ]]; then
    ROOT=$(readlink -f "${ROOT}")
fi

CFLAGS="-D__ALIP_WAS_HERE -O0 -g -ggdb3 -D__PINK_IS_BEHIND_THE_WALL"
LD_LIBRARY_PATH="${ROOT}/pinktrace/.libs:${ROOT}/sydbox/.libs:${LD_LIBRARY_PATH}"

export CFLAGS
export LD_LIBRARY_PATH
