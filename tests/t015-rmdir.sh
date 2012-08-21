#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='sandbox rmdir(2)'
. ./test-lib.sh

test_expect_success setup '
    mkdir dir0 &&
    mkdir dir2 &&
    mkdir dir3
'

test_expect_success 'deny rmdir(NULL) with EFAULT' '
    sydbox -ESYDBOX_TEST_EFAULT=1 -- emily rmdir
'

test_expect_success 'deny rmdir()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily rmdir dir0 &&
    test_path_is_dir dir0
'

test_expect_success 'deny rmdir() for non-existant directory' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily rmdir dir1-non-existant
'

test_expect_success 'whitelist rmdir()' '
    sydbox -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily rmdir dir2 &&
    test_path_is_missing dir2
'

test_expect_success 'blacklist rmdir()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily rmdir dir3 &&
    test_path_is_dir dir3
'

test_expect_success 'blacklist rmdir() for non-existant directory' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily rmdir dir4-non-existant
'

test_done
