#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox truncate(2)'
. ./test-lib.sh

test_expect_success setup '
    echo foo > file0 &&
    echo foo > file2 &&
    echo foo > file3 &&
    echo foo > file4
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf /non/existant/path symlink-dangling &&
    ln -sf file2 symlink-file2 &&
    ln -sf file4 symlink-file4
'

test_expect_success 'deny truncate(NULL) with EFAULT' '
    sydbox -ESYDBOX_TEST_EFAULT=1 -- emily truncate
'

test_expect_success 'deny truncate()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily truncate file0 &&
    test_path_is_non_empty file0
'

test_expect_success 'deny truncate() for non-existant file' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily truncate file1-non-existant
'

test_expect_success SYMLINKS 'deny truncate() for symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily truncate symlink-file2 &&
    test_path_is_non_empty file2
'

test_expect_success SYMLINKS 'deny truncate() for dangling symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily truncate symlink-dangling
'

test_expect_success 'allow truncate()' '
    sydbox -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily truncate file3 &&
    test_path_is_empty file3
'

test_expect_success SYMLINKS 'allow truncate() for symbolic link' '
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily truncate symlink-file4 &&
    test_path_is_empty file4
'

test_done
