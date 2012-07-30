#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox chown(2)'
. ./test-lib.sh

test_expect_success setup '
    rm -f file-non-existant &&
    touch file0 &&
    touch file1 &&
    touch file2 &&
    touch file3
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf /non/existant/file symlink-dangling &&
    ln -sf file1 symlink-file1 &&
    ln -sf file3 symlink-file3
'

test_expect_success 'deny chown(NULL) with EFAULT' '
    sydbox -ESYDBOX_TEST_EFAULT=1 -- emily chown
'

test_expect_success 'deny chown()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily chown file0
'

test_expect_success 'deny chown() for non-existant file' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily chown file-non-existant
'

test_expect_success SYMLINKS 'deny chown() for symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily chown symlink-file1
'

test_expect_success SYMLINKS 'deny chown() for dangling symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily chown symlink-dangling
'

test_expect_success 'allow chown()' '
    sydbox -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily chown file2
'

test_expect_success SYMLINKS 'allow chown() for symbolic link' '
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily chown symlink-file3
'

test_done
