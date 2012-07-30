#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox mkdir(2)'
. ./test-lib.sh

test_expect_success setup '
    mkdir dir1
'

test_expect_success 'deny mkdir(NULL) with EFAULT' '
    sydbox -ESYDBOX_TEST_EFAULT=1 -- emily mkdir
'

test_expect_success 'deny mkdir()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily mkdir dir0-non-existant &&
    test_path_is_missing dir0-non-existant
'

test_expect_success 'deny mkdir() for existant directory' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EEXIST=1 \
        -m core/sandbox/write:deny \
        -- emily mkdir dir1
'

test_expect_success 'allow mkdir()' '
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily mkdir dir2-non-existant &&
    test_path_is_dir dir2-non-existant
'

test_done
