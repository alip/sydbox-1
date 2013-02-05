#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012, 2013 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='sandbox chown(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success 'deny chown(NULL) with EFAULT' '
    sydbox -- emily chown -e EFAULT
'

test_expect_success 'deny chown($file)' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chown -e EPERM "$f"
'

test_expect_success 'deny chown($nofile)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chown -e ENOENT "$f"
'

test_expect_success SYMLINKS 'deny chown($symlink-file)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chown -e EPERM "$l"
'

test_expect_success SYMLINKS 'deny chown($symlink-dangling)' '
    f="no-$(unique_file)" &&
    l="bad-$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chown -e ENOENT "$l"
'

test_expect_success 'blacklist chown($file)' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chown -e EPERM "$f"
'

test_expect_success 'blacklist chown($nofile)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chown -e ENOENT "$f"
'

test_expect_success SYMLINKS 'blacklist chown($symlink-file)' '
    f="unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chown -e EPERM "$l"
'

test_expect_success SYMLINKS 'blacklist chown($symlink-dangling)' '
    f="no-$(unique_file)" &&
    l="bad-$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chown -e ENOENT "$l"
'

test_expect_success 'whitelist chown($file)' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily chown -e ERRNO_0 "$f"
'

test_expect_success SYMLINKS 'whitelist chown($symlink-file)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily chown -e ERRNO_0 "$l"
'

test_done
