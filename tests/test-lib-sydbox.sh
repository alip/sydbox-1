#!/bin/sh
# vim: set noet ts=8 sts=8 sw=8 tw=80 :
# Copyright 2013 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

#
# Additions to test-lib-functions.sh
#
test_path_is_symlink() {
	if ! [ -h "$1" ]
	then
		echo "Symbolic link $1 doesn't exist. $*"
		false
	fi
}

test_path_is_readable () {
	if ! [ -r "$1" ]
	then
		echo "Path $1 isn't readable. $*"
		false
	fi
}

test_path_is_not_readable () {
	if [ -r "$1" ]
	then
		echo "Path $1 is readable. $*"
		false
	fi
}

test_path_is_writable () {
	if ! [ -w "$1" ]
	then
		echo "Path $1 isn't writable. $*"
		false
	fi
}

test_path_is_not_writable () {
	if [ -w "$1" ]
	then
		echo "Path $1 is writable. $*"
		false
	fi
}

test_path_is_empty() {
	if [ -s "$1" ]
	then
		echo "File $1 isn't empty. $*"
		false
	fi
}

test_path_is_non_empty() {
	if ! [ -s "$1" ]
	then
		echo "File $1 is empty. $*"
		false
	fi
}

test_must_violate() {
	retval=0
	old_SYDBOX_TEST_OPTIONS="$SYDBOX_TEST_OPTIONS"
	SYDBOX_TEST_OPTIONS="$SYDBOX_TEST_OPTIONS -mcore/violation/exit_code:0"
	export SYDBOX_TEST_OPTIONS
	"$@"
	exit_code=$?
	if test $exit_code -eq 0
	then
		echo >&2 "test_must_violate: command succeeded. $*"
		retval=1
	elif test $exit_code -gt 129 -a $exit_code -le 192
	then
		echo >&2 "test_must_violate: died by signal: $*"
		retval=1
	elif test $exit_code = 127
	then
		echo >&2 "test_must_violate: command not found: $*"
		retval=1
	elif test $exit_code -ne 128
	then
		echo >&2 "test_must_violate: abnormal exit with code:$exit_code $*"
		retval=1
	fi
	SYDBOX_TEST_OPTIONS="$old_SYDBOX_TEST_OPTIONS"
	export SYDBOX_TEST_OPTIONS
	return $retval
}

#
# Generate unique file/dir name for a testcase.
# Usage: test_tempname $dir $prefix
# Note: We don't care about security here!
#
test_tempnam() {
	case $# in
	2) ;;
	*) error "bug in the test script: not 2 parameters to test_tempnam" ;;
	esac

	"$PERL_PATH" \
		-e 'use File::Temp;' \
		-e 'print File::Temp::tempnam($ARGV[0], $ARGV[1]);' \
		-- "$@"
	exit_code=$?
	if test $exit_code != 0
	then
		error "bug in the test library: test_tempnam() exited with $exit_code"
	fi
}

test_tempnam_cwd() {
	basename "$(test_tempnam . "$1")"
	exit_code=$?
	if test $exit_code != 0
	then
		error "bug in the test library: basename exited with $exit_code"
	fi
}

test_unique_with_prefix() {
	prefix="$1"
	optpre="$2"

	printf "%s-%s_%s.%s" "$prefix" "$optpre" "$(test_tempnam_cwd . "")" "$test_count"
}

# Shorthand functions for convenience
unique_file() {
	test_unique_with_prefix "file" "$1"
}

unique_dir() {
	test_unique_with_prefix "dir" "$1"
}

unique_link() {
	test_unique_with_prefix "link" "$1"
}

unique_fifo() {
	test_unique_with_prefix "fifo" "$1"
}
