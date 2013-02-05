#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012, 2013 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='sandbox creat(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success 'deny creat()' '
    f="no-$(file_uniq)" &&
    rm -f "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily creat -e EPERM "$f" &&
    test_path_is_missing "$f"
'

test_expect_success SYMLINKS 'deny creat() for dangling symbolic link' '
    f="no-$(file_uniq)" &&
    l="$(link_uniq)" &&
    rm -f "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily creat -e EPERM "$l" &&
    test_path_is_missing "$f"
'

test_expect_success 'whitelist creat()' '
    f="no-$(file_uniq)" &&
    rm -f "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily creat -e ERRNO_0 "$f" "3" &&
    test_path_is_non_empty "$f"
'

test_expect_success 'blacklist creat()' '
    f="no-$(file_uniq)" &&
    rm -f "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily creat -e EPERM "$f" &&
    test_path_is_missing "$f"
'

test_expect_success SYMLINKS 'blacklist creat() for dangling symbolic link' '
    f="no-$(file_uniq)" &&
    l="$(link_uniq)" &&
    rm -f "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily creat -e EPERM "$l" &&
    test_path_is_missing "$f"
'

test_done
