#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox chown(2)'
. ./test-lib.sh

test_expect_success setup '
    rm -f file-non-existant &&
    touch file0 &&
    touch file1 &&
    touch file2 &&
    touch file3 &&
    touch file4 &&
    touch file5
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf /non/existant/file symlink-dangling &&
    ln -sf file1 symlink-file1 &&
    ln -sf file3 symlink-file3 &&
    ln -sf file5 symlink-file5
'

test_expect_success 'deny chown(NULL) with EFAULT' '
    sydbox -- emily chown --errno=EFAULT
'

test_expect_success 'deny chown()' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chown --errno=EPERM file0
'

test_expect_success 'deny chown() for non-existant file' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chown --errno=EPERM file-non-existant
'

test_expect_success SYMLINKS 'deny chown() for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chown --errno=EPERM symlink-file1
'

test_expect_success SYMLINKS 'deny chown() for dangling symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chown --errno=EPERM symlink-dangling
'

test_expect_success 'blacklist chown()' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chown --errno=EPERM file2
'

test_expect_success 'blacklist chown() for non-existant file' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chown --errno=EPERM file-non-existant
'

test_expect_success SYMLINKS 'blacklist chown() for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chown --errno=EPERM symlink-file3
'

test_expect_success SYMLINKS 'blacklist chown() for dangling symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chown --errno=EPERM symlink-dangling
'

test_expect_success 'whitelist chown()' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily chown --errno=ERRNO_0 file4
'

test_expect_success SYMLINKS 'whitelist chown() for symbolic link' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily chown --errno=ERRNO_0 symlink-file5
'

test_done
