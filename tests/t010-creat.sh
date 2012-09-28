#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='sandbox creat(2)'
. ./test-lib.sh

test_expect_success 'deny creat()' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily creat -e EPERM nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success SYMLINKS 'deny creat() for dangling symbolic link' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily creat -e EPERM link.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'whitelist creat()' '
    rm -f nofile.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily creat -e ERRNO_0 nofile.$test_count "3" &&
    test_path_is_non_empty nofile.$test_count
'

test_expect_success 'blacklist creat()' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily creat -e EPERM nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success SYMLINKS 'blacklist creat() for dangling symbolic link' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily creat -e EPERM link.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_done
