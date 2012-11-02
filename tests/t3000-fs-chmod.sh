#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='sandbox chmod()'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success 'chmod($file) returns ERRNO_0' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    sydbox -- emily chmod -e ERRNO_0 -m 000 file.$test_count &&
    test_path_is_not_readable file.$test_count &&
    test_path_is_not_writable file.$test_count
'

test_expect_success 'chmod($symlink) returns ERRNO_0' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    ln -sf file.$test_count link.$test_count
    sydbox -- emily chmod -e ERRNO_0 -m 000 link.$test_count
    test_path_is_not_readable file.$test_count &&
    test_path_is_not_writable file.$test_count
'

test_expect_success 'chmod(NULL) returns EFAULT' '
    sydbox -- emily chmod -e EFAULT
'

test_expect_success 'chmod($nofile) returns ENOENT' '
    rm -f nofile.$test_count &&
    sydbox -- emily chmod -e ENOENT -m 000 nofile.$test_count
'

test_expect_success SYMLINKS 'chmod($symlink-self) returns ELOOP' '
    ln -sf self-link.$test_count self-link.$test_count &&
    sydbox -- emily chmod -e ELOOP -m 000 self-link.$test_count
'

test_expect_success SYMLINKS 'chmod($symlink-circular) returns ELOOP' '
    ln -sf loop0.$test_count loop1.$test_count &&
    ln -sf loop1.$test_count loop0.$test_count &&
    sydbox -- emily chmod -e ELOOP -m 000 loop0.$test_count
'

test_expect_success 'deny chmod($file)' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chmod -e EPERM -m 000 file.$test_count &&
    test_path_is_readable file.$test_count &&
    test_path_is_writable file.$test_count
'

test_expect_success 'deny chmod($nofile)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chmod -e ENOENT -m 000 nofile.$test_count
'

test_expect_success SYMLINKS 'deny chmod($symlink)' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chmod -e EPERM -m 000 link.$test_count &&
    test_path_is_readable file.$test_count &&
    test_path_is_writable file.$test_count
'

test_expect_success SYMLINKS 'deny chmod($symlink-dangling)' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count dangling-link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chmod -e ENOENT -m 000 dangling-link.$test_count
'

test_expect_success 'blacklist chmod($file)' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e EPERM -m 000 file.$test_count &&
    test_path_is_readable file.$test_count &&
    test_path_is_writable file.$test_count
'

test_expect_success 'blacklist chmod($nofile)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e ENOENT -m 000 nofile.$test_count
'

test_expect_success SYMLINKS 'blacklist chmod($symlink)' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e EPERM -m 000 link.$test_count &&
    test_path_is_readable file.$test_count &&
    test_path_is_writable file.$test_count
'

test_expect_success SYMLINKS 'blacklist chmod($symlink-dangling)' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count dangling-link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e ENOENT -m 000 dangling-link.$test_count
'

test_expect_success 'whitelist chmod($file)' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e ERRNO_0 -m 000 file.$test_count &&
    test_path_is_not_readable file.$test_count &&
    test_path_is_not_writable file.$test_count
'

test_expect_success SYMLINKS 'whitelist chmod($symlink)' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e ERRNO_0 -m 000 link.$test_count &&
    test_path_is_not_readable file.$test_count &&
    test_path_is_not_writable file.$test_count
'

test_expect_success SYMLINKS 'deny whitelisted chmod($symlink-outside)' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    mkdir dir.$test_count &&
    ln -sf ../file.$test_count dir.$test_count/link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/dir.$test_count/**" \
        -- emily chmod -e EPERM -m 000 dir.$test_count/link.$test_count &&
    test_path_is_readable file.$test_count &&
    test_path_is_writable file.$test_count
'

test_done
