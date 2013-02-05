#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2013 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

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

    "$PERL_PATH" -e 'use File::Temp;' \
                 -e 'print File::Temp::tempnam($ARGV[0], $ARGV[1]);' \
                 -- "$@"
    exit_code=$?
    if test $exit_code != 0; then
        error "bug in the test library: test_tempnam() exited with $exit_code"
    fi
}

test_tempnam_cwd() {
    basename "$(test_tempnam . "$1")"
    exit_code=$?
    if test $exit_code != 0; then
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
