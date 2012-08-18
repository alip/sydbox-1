#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

# chmod()
# returns EFAULT on NULL:               yes
# returns ENOENT if file doesn't exist: yes
# returns EEXIST if file exists:        no
# resolves symbolic links:              yes

test_description='sandbox chmod()'
. ./test-lib.sh

test_expect_success setup '
    mkdir dir0 &&
    touch file0 && chmod 600 file0 &&
    touch file1 && chmod 600 file1 &&
    touch file2 && chmod 600 file2 &&
    touch file3 && chmod 600 file3 &&
    touch file4 && chmod 600 file4 &&
    touch file5 && chmod 600 file5 &&
    touch file6 && chmod 600 file6 &&
    touch file7 && chmod 600 file7 &&
    touch file8 && chmod 600 file8
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf symlink-self symlink-self
    ln -sf symlink-loop0 symlink-loop1
    ln -sf symlink-loop1 symlink-loop0
    ln -sf nofile symlink-dangling &&
    ln -sf file1 symlink-file1 &&
    ln -sf file3 symlink-file3 &&
    ln -sf file5 symlink-file5 &&
    ln -sf file7 symlink-file7 &&
    ln -sf ../file8 dir0/symlink-file8
'

test_expect_success 'chmod($file) returns ERRNO_0' '
    sydbox -- emily chmod -e ERRNO_0 -m 000 file0 &&
    test_path_is_not_readable file0 &&
    test_path_is_not_writable file0
'

test_expect_success 'chmod($symlink) returns ERRNO_0' '
    sydbox -- emily chmod -e ERRNO_0 -m 000 symlink-file1
    test_path_is_not_readable file1 &&
    test_path_is_not_writable file1
'

test_expect_success 'chmod(NULL) returns EFAULT' '
    sydbox -- emily chmod -e EFAULT
'

test_expect_success 'chmod($nofile) returns ENOENT' '
    sydbox -- emily chmod -e ENOENT -m 000 nofile
'

test_expect_success SYMLINKS 'chmod($symlink-self) returns ELOOP' '
    sydbox -- emily chmod -e ELOOP -m 000 symlink-self
'

test_expect_success SYMLINKS 'chmod($symlink-circular) returns ELOOP' '
    sydbox -- emily chmod -e ELOOP -m 000 symlink-loop0
'

test_expect_success 'deny chmod($file)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chmod -e EPERM -m 000 file2 &&
    test_path_is_readable file2 &&
    test_path_is_writable file2
'

test_expect_success 'deny chmod($nofile)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chmod -e ENOENT -m 000 nofile
'

test_expect_success SYMLINKS 'deny chmod($symlink)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chmod -e EPERM -m 000 symlink-file3 &&
    test_path_is_readable file3 &&
    test_path_is_writable file3
'

test_expect_success SYMLINKS 'deny chmod($symlink-dangling)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chmod -e ENOENT -m 000 symlink-dangling
'

test_expect_success 'blacklist chmod($file)' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e EPERM -m 000 file4 &&
    test_path_is_readable file4 &&
    test_path_is_writable file4
'

test_expect_success 'blacklist chmod($nofile)' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e ENOENT -m 000 nofile
'

test_expect_success SYMLINKS 'blacklist chmod($symlink)' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e EPERM -m 000 symlink-file5 &&
    test_path_is_readable file5 &&
    test_path_is_writable file5
'

test_expect_success SYMLINKS 'blacklist chmod($symlink-dangling)' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e ENOENT -m 000 symlink-dangling
'

test_expect_success 'whitelist chmod($file)' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e ERRNO_0 -m 000 file6 &&
    test_path_is_not_readable file6 &&
    test_path_is_not_writable file6
'

test_expect_success SYMLINKS 'whitelist chmod($symlink)' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e ERRNO_0 -m 000 symlink-file7 &&
    test_path_is_not_readable file7 &&
    test_path_is_not_writable file7
'

test_expect_success SYMLINKS 'deny whitelisted chmod($symlink-outside)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/dir0/**" \
        -- emily chmod -e EPERM -m 000 dir0/symlink-file8 &&
    test_path_is_readable file8 &&
    test_path_is_writable file8
'

test_done
