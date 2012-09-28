#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='sandbox chown(2)'
. ./test-lib.sh

test_expect_success 'deny chown(NULL) with EFAULT' '
    sydbox -- emily chown -e EFAULT
'

test_expect_success 'deny chown($file)' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chown -e EPERM file.$test_count
'

test_expect_success 'deny chown($nofile)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chown -e ENOENT nofile.$test_count
'

test_expect_success SYMLINKS 'deny chown($symlink-file)' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chown -e EPERM link.$test_count
'

test_expect_success SYMLINKS 'deny chown($symlink-dangling)' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link-dangling.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chown -e ENOENT symlink-dangling
'

test_expect_success 'blacklist chown($file)' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chown -e EPERM file.$test_count
'

test_expect_success 'blacklist chown($nofile)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chown -e ENOENT nofile.$test_count
'

test_expect_success SYMLINKS 'blacklist chown($symlink-file)' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chown -e EPERM link.$test_count
'

test_expect_success SYMLINKS 'blacklist chown($symlink-dangling)' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link-dangling.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chown -e ENOENT symlink-dangling
'

test_expect_success 'whitelist chown($file)' '
    touch file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily chown -e ERRNO_0 file.$test_count
'

test_expect_success SYMLINKS 'whitelist chown($symlink-file)' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily chown -e ERRNO_0 link.$test_count
'

test_done
