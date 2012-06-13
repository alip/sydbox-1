#!/bin/sh

if test "${1%.sh}" = "$1" -o -z "$PANDORA_CHECK_OPTS"
then
	exec "$1"
fi

exec "$1" $PANDORA_CHECK_OPTS
