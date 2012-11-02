#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='sandbox truncate(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_failure 'deny truncate(NULL) with EFAULT' '
    sydbox -- emily -e EFAULT truncate
'

test_expect_failure 'deny truncate()' '
    : > file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily truncate -e EPERM file.$test_count &&
    test_path_is_non_empty file.$test_count
'

test_expect_failure 'deny truncate() for non-existant file' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily truncate -e EPERM nofile.$test_count
'

test_expect_failure SYMLINKS 'deny truncate() for symbolic link' '
    echo hello syd > file.$test_count &&
    ln -sf link.$test_count file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily truncate -e EPERM link.$test_count &&
    test_path_is_non_empty file.$test_count
'

test_expect_failure SYMLINKS 'deny truncate() for dangling symbolic link' '
    rm -f nofile.$test_count &&
    ln -sf nolink.$test_count nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily truncate nolink.$test_count
'

test_expect_failure 'whitelist truncate()' '
    echo hello syd > file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily truncate file.$test_count &&
    test_path_is_empty file.$test_count
'

test_expect_failure SYMLINKS 'whitelist truncate() for symbolic link' '
    echo hello syd > file.$test_count &&
    ln -sf link.$test_count file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily truncate -e ERRNO_0 link.$test_count &&
    test_path_is_empty file.$test_count
'

test_done
