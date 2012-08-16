#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox creat(2)'
. ./test-lib.sh

test_expect_success setup '
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf file1-non-existant symlink-file1
'

test_expect_success 'deny creat()' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily creat -e EPERM file0-non-existant &&
    test_path_is_missing file0-non-existant
'

test_expect_success SYMLINKS 'deny creat() for dangling symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily creat -e EPERM symlink-file1 &&
    test_path_is_missing file1-non-existant
'

test_expect_success 'whitelist creat()' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily creat -e ERRNO_0 file2-non-existant "3" &&
    test_path_is_non_empty file2-non-existant
'

test_expect_success 'blacklist creat()' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily creat -e EPERM file0-non-existant &&
    test_path_is_missing file0-non-existant
'

test_expect_success SYMLINKS 'blacklist creat() for dangling symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily creat -e EPERM symlink-file1 &&
    test_path_is_missing file1-non-existant
'

test_done
