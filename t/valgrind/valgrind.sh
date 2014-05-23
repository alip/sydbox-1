#!/bin/sh

base=$(basename "$0")

TOOL_OPTIONS='--leak-check=no'

test -z "$SYD_VALGRIND_ENABLED" &&
exec "$SYD_VALGRIND"/../../"$base" "$@"

case "$SYD_VALGRIND_MODE" in
memcheck-fast)
	;;
memcheck)
	VALGRIND_VERSION=$(valgrind --version)
	VALGRIND_MAJOR=$(expr "$VALGRIND_VERSION" : '[^0-9]*\([0-9]*\)')
	VALGRIND_MINOR=$(expr "$VALGRIND_VERSION" : '[^0-9]*[0-9]*\.\([0-9]*\)')
	test 3 -gt "$VALGRIND_MAJOR" ||
	test 3 -eq "$VALGRIND_MAJOR" -a 4 -gt "$VALGRIND_MINOR" ||
	TOOL_OPTIONS="$TOOL_OPTIONS --track-origins=yes"
	;;
*)
	TOOL_OPTIONS="--tool=$SYD_VALGRIND_MODE"
esac

exec valgrind -q --error-exitcode=126 \
	--gen-suppressions=all \
	--suppressions="$SYD_VALGRIND/default.supp" \
	$TOOL_OPTIONS \
	--log-fd=4 \
	--input-fd=4 \
	$SYD_VALGRIND_OPTIONS \
	"$SYD_VALGRIND"/../../"$base" "$@"
