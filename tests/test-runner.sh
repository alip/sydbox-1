#!/bin/sh

if test "${1%.sh}" = "$1" -o -z "$SYDBOX_CHECK_OPTS"
then
	exec "$1"
fi

exec "$1" $SYDBOX_CHECK_OPTS
