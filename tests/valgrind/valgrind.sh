#!/bin/sh

TRACK_ORIGINS=

VALGRIND_VERSION=$(valgrind --version)
VALGRIND_MAJOR=$(expr "$VALGRIND_VERSION" : '[^0-9]*\([0-9]*\)')
VALGRIND_MINOR=$(expr "$VALGRIND_VERSION" : '[^0-9]*[0-9]*\.\([0-9]*\)')
test 3 -gt "$VALGRIND_MAJOR" ||
test 3 -eq "$VALGRIND_MAJOR" -a 4 -gt "$VALGRIND_MINOR" ||
TRACK_ORIGINS=--track-origins=yes

exec valgrind -q --error-exitcode=126 \
	--leak-check=full \
	--suppressions="$SYDBOX_VALGRIND"/default.supp \
	--gen-suppressions=all \
	$TRACK_ORIGINS \
	--log-fd=4 \
	--input-fd=4 \
	$SYDBOX_VALGRIND_OPTIONS \
	"$SYDBOX" $SYDBOX_OPTIONS "$@"
