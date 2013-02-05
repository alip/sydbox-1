#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012, 2013 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='sandbox mkdir(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success 'deny mkdir(NULL) with EFAULT' '
    sydbox -- emily mkdir -e EFAULT
'

test_expect_success 'deny mkdir()' '
    d="no-$(dir_uniq)"
    rm -rf "$d" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily mkdir -e EPERM "$d" &&
    test_path_is_missing "$d"
'

test_expect_success 'deny mkdir() for existant directory' '
    d="$(dir_uniq)"
    mkdir "$d" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily mkdir -e EEXIST "$d"
'

test_expect_success 'whitelist mkdir()' '
    d="no-$(dir_uniq)"
    rm -rf "$d" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily mkdir -e ERRNO_0 "$d" &&
    test_path_is_dir "$d"
'

test_expect_success 'whitelist mkdir() for existant directory' '
    d="$(dir_uniq)"
    mkdir "$d" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily mkdir -e EEXIST "$d"
'

test_expect_success 'blacklist mkdir()' '
    d="no-$(dir_uniq)"
    rm -rf "$d" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily mkdir -e EPERM "$d" &&
    test_path_is_missing "$d"
'

test_expect_success 'deny mkdir() for existant directory' '
    d="$(dir_uniq)"
    mkdir "$d" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily mkdir -e EEXIST "$d"
'

test_done
