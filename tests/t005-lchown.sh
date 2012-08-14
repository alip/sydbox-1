#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox lchown(2)'
. ./test-lib.sh

test_expect_success SYMLINKS setup-symlinks '
    touch file0 &&
    ln -sf file0 symlink-file0 &&
    touch file1 &&
    ln -sf file1 symlink-file1 &&
    touch file2 &&
    ln -sf file2 symlink-file2
'

test_expect_success 'deny lchown(NULL) with EFAULT' '
    sydbox -- emily lchown -e EFAULT
'

test_expect_success SYMLINKS 'deny lchown()' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily lchown -e EPERM symlink-file0
'

test_expect_success SYMLINKS 'deny lchown for non-existant file' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily lchown -e ENOENT file-non-existant
'

test_expect_success SYMLINKS 'blacklist lchown()' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily lchown -e EPERM symlink-file1
'

test_expect_success SYMLINKS 'blacklist lchown for non-existant file' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily lchown -e ENOENT file-non-existant
'

test_expect_success SYMLINKS 'whitelist lchown()' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily lchown -e ERRNO_0 symlink-file2
'

test_done
