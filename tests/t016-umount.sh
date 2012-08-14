#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox umount(2)'
. ./test-lib.sh

test_expect_success setup '
    mkdir mnt0 &&
    mkdir mnt2 &&
    mkdir mnt3 &&
    mkdir mnt5
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf /non/existant/directory symlink-dangling &&
    ln -sf mnt2 symlink-mnt2
    ln -sf mnt5 symlink-mnt5
'

test_expect_success 'deny umount(NULL) with EFAULT' '
    sydbox -ESYDBOX_TEST_EFAULT=1 -- emily umount
'

test_expect_success 'deny umount()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily umount mnt0
'

test_expect_success 'deny umount() for non-existant directory' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily umount mnt1-non-existant
'

test_expect_success SYMLINKS 'deny umount() for symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily umount symlink-mnt2
'

test_expect_success SYMLINKS 'deny umount() for dangling symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily umount symlink-dangling
'

test_expect_success 'blacklist umount()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily umount mnt3
'

test_expect_success 'blacklist umount() for non-existant directory' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily umount mnt4-non-existant
'

test_expect_success SYMLINKS 'blacklist umount() for symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily umount symlink-mnt5
'

test_expect_success SYMLINKS 'blacklist umount() for dangling symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily umount symlink-dangling
'

test_done
