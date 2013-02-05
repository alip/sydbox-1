#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012, 2013 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='sandbox chmod(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success 'chmod($file) returns ERRNO_0' '
    f="$(file_uniq)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    sydbox -- emily chmod -e ERRNO_0 -m 000 "$f" &&
    test_path_is_not_readable "$f" &&
    test_path_is_not_writable "$f"
'

test_expect_success SYMLINKS 'chmod($symlink) returns ERRNO_0' '
    f="$(file_uniq)" &&
    l="$(link_uniq)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" "$l" &&
    sydbox -- emily chmod -e ERRNO_0 -m 000 "$l"
    test_path_is_not_readable "$f" &&
    test_path_is_not_writable "$f"
'

test_expect_success 'chmod(NULL) returns EFAULT' '
    sydbox -- emily chmod -e EFAULT
'

test_expect_success 'chmod("") returns ENOENT' '
    sydbox -- emily chmod -e ENOENT -m 000 ""
'

test_expect_success 'chmod($nofile) returns ENOENT' '
    f="no-$(file_uniq)" &&
    rm -f "$f" &&
    sydbox -- emily chmod -e ENOENT -m 000 "$f"
'

test_expect_success 'chmod($noaccess/$file) returns EACCES' '
    d="no-access-$(dir_uniq)" &&
    f="$(file_uniq)" &&
    mkdir "$d" &&
    touch "$d"/"$f" &&
    chmod 600 "$d"/"$f" &&
    test_when_finished "chmod 700 $d" && chmod 000 "$d" &&
    sydbox -- emily chmod -e EACCES -m 000 "$d"/"$f" &&
    chmod 700 "$d" &&
    test_path_is_readable "$d"/"$f" &&
    test_path_is_writable "$d"/"$f"
'

test_expect_success 'chmod($nodir/$file) returns ENOTDIR' '
    d="non-$(dir_uniq)" &&
    touch "$d" &&
    sydbox -- emily chmod -e ENOTDIR -m 000 "$d"/foo
'

test_expect_success SYMLINKS 'chmod($symlink-self) returns ELOOP' '
    l="self-$(link_uniq)" &&
    ln -sf "$l" "$l" &&
    sydbox -- emily chmod -e ELOOP -m 000 "$l"
'

test_expect_success SYMLINKS 'chmod($symlink-circular) returns ELOOP' '
    l0="loop0-$(link_uniq)" &&
    l1="loop1-$(link_uniq)" &&
    ln -sf "$l0" "$l1" &&
    ln -sf "$l1" "$l0" &&
    sydbox -- emily chmod -e ELOOP -m 000 "$l0"
'

test_expect_success 'deny chmod($file)' '
    f="$(file_uniq)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chmod -e EPERM -m 000 "$f" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success 'deny chmod($nofile)' '
    f="no-$(file_uniq)" &&
    rm -f "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chmod -e ENOENT -m 000 "$f"
'

test_expect_success SYMLINKS 'deny chmod($symlink)' '
    f="$(file_uniq)" &&
    l="$(link_uniq)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chmod -e EPERM -m 000 "$l" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success SYMLINKS 'deny chmod($symlink-dangling)' '
    f="no-$(file_uniq)" &&
    l="bad-$(link_uniq)" &&
    rm -f "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chmod -e ENOENT -m 000 "$l"
'

test_expect_success 'blacklist chmod($file)' '
    touch "$f" &&
    chmod 600 "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e EPERM -m 000 "$f" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success 'blacklist chmod($nofile)' '
    f="no-$(file_uniq)" &&
    rm -f "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e ENOENT -m 000 "$f"
'

test_expect_success SYMLINKS 'blacklist chmod($symlink)' '
    f="$(file_uniq)" &&
    l="$(link_uniq)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e EPERM -m 000 "$l" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success SYMLINKS 'blacklist chmod($symlink-dangling)' '
    f="no-$(file_uniq)" &&
    l="bad-$(link_uniq)" &&
    rm -f "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e ENOENT -m 000 "$l"
'

test_expect_success 'whitelist chmod($file)' '
    f="$(file_uniq)" &&
    l="$(link_uniq)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e ERRNO_0 -m 000 "$f" &&
    test_path_is_not_readable "$f" &&
    test_path_is_not_writable "$f"
'

test_expect_success SYMLINKS 'whitelist chmod($symlink)' '
    f="$(file_uniq)" &&
    l="$(link_uniq)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" "$l" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e ERRNO_0 -m 000 "$l" &&
    test_path_is_not_readable "$f" &&
    test_path_is_not_writable "$f"
'

test_expect_success SYMLINKS 'deny whitelisted chmod($symlink-outside)' '
    f="$(file_uniq)" &&
    l="$(link_uniq)" &&
    d="$(dir_uniq)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    mkdir "$d" &&
    ln -sf ../"$f" "$d"/"$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/"$d"/**" \
        -- emily chmod -e EPERM -m 000 "$d"/"$l" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_done
