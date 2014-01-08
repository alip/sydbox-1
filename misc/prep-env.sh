#!/bin/sh -x

CFLAGS="-D__ALIP_WAS_HERE -O0 -g -ggdb3 -D__PINK_IS_BEHIND_THE_WALL"
PKG_CONFIG_PATH="$HOME/pink/lib/pkgconfig:$PKG_CONFIG_PATH"

export CFLAGS
export PKG_CONFIG_PATH
