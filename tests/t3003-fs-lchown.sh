#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='sandbox lchown(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success 'deny lchown(NULL) with EFAULT' '
    sydbox -- emily lchown -e EFAULT
'

test_expect_success SYMLINKS 'deny lchown($symlink-file)' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily lchown -e EPERM link.$test_count
'

test_expect_success SYMLINKS 'deny lchown($nofile)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily lchown -e ENOENT nofile.$test_count
'

test_expect_success SYMLINKS 'blacklist lchown($symlink-file)' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily lchown -e EPERM link.$test_count
'

test_expect_success SYMLINKS 'blacklist lchown($nofile)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily lchown -e ENOENT nofile.$test_count
'

test_expect_success SYMLINKS 'whitelist lchown($symlink-file)' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily lchown -e ERRNO_0 link.$test_count
'

test_done
