#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox lchown(2)'
. ./test-lib.sh
prog=t005_lchown

test_expect_success SYMLINKS setup-symlinks '
    touch file0 &&
    ln -sf file0 symlink-file0 &&
    touch file2 &&
    ln -sf file2 symlink-file2
'

test_expect_success 'deny lchown(NULL) with EFAULT' '
    sydbox -ESYDBOX_TEST_EFAULT=1 -- emily lchown
'

test_expect_success SYMLINKS 'deny lchown()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily lchown symlink-file0
'

test_expect_success SYMLINKS 'deny lchown for non-existant file' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily lchown file1-non-existant
'

test_expect_success SYMLINKS 'allow lchown()' '
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily lchown symlink-file2
'

test_done
