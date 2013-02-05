#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012, 2013 Ali Polatel <alip@exherbo.org>
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
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily lchown -e EPERM "$l"
'

test_expect_success SYMLINKS 'deny lchown($nofile)' '
    f="no-$(unique_file)" &&
    rm -f "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily lchown -e ENOENT "$f"
'

test_expect_success SYMLINKS 'blacklist lchown($symlink-file)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily lchown -e EPERM "$l"
'

test_expect_success SYMLINKS 'blacklist lchown($nofile)' '
    f="no-$(unique_file)" &&
    rm -f "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily lchown -e ENOENT "$f"
'

test_expect_success SYMLINKS 'whitelist lchown($symlink-file)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily lchown -e ERRNO_0 "$l"
'

test_done
