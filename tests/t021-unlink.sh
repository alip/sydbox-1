#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='sandbox unlink(2)'
. ./test-lib.sh

test_expect_success setup '
    touch file0 &&
    touch file2 &&
    touch file3
'

test_expect_success 'deny unlink(NULL) with EFAULT' '
    sydbox -ESYDBOX_TEST_EFAULT=1 -- emily unlink
'

test_expect_success 'deny unlink()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily unlink file0 &&
    test_path_is_file file0
'

test_expect_success 'deny unlink() for non-existant file' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily unlink file1-non-existant
'

test_expect_success 'allow unlink()' '
    sydbox -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily unlink file2 &&
    test_path_is_missing file2
'

test_expect_success 'blacklist unlink()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily unlink file3 &&
    test_path_is_file file3
'

test_expect_success 'blacklist unlink() for non-existant file' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily unlink file4-non-existant
'

test_done
