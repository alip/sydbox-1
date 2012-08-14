#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox open(2)'
. ./test-lib.sh

test_expect_success setup '
    touch file0 &&
    touch file1 &&
    touch file5 &&
    touch file7 &&
    touch file9 &&
    touch file11 &&
    touch file12 &&
    touch file15 &&
    touch file16 &&
    touch file19 &&
    touch file20 &&
    touch file23 &&
    touch file24 &&
    touch file27 &&
    touch file31 &&
    touch file33 &&
    touch file35 &&
    touch file37 &&
    touch file38 &&
    touch file41
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf /non/existant/file symlink-dangling &&
    ln -sf file1 symlink-file1 &&
    ln -sf file3-non-existant symlink-file3 &&
    ln -sf file6-non-existant symlink-file6 &&
    ln -sf file9 symlink-file9 &&
    ln -sf file12 symlink-file12 &&
    ln -sf file13-non-existant symlink-file13 &&
    ln -sf file29-non-existant symlink-file29 &&
    ln -sf file32-non-existant symlink-file32 &&
    ln -sf file35 symlink-file35 &&
    ln -sf file39-non-existant symlink-file39
'

test_expect_success 'deny open(NULL) with EFAULT' '
    sydbox -- emily open -e EFAULT
'

test_expect_success 'whitelist O_RDONLY' '
    sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e ERRNO_0 -m rdonly file0
'

test_expect_success SYMLINKS 'whitelist O_RDONLY for symbolic link' '
    sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e ERRNO_0 -m rdonly symlink-file1
'

test_expect_success 'deny O_RDONLY|O_CREAT' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m rdonly -c file2-non-existant &&
    test_path_is_missing file2-non-existant
'

test_expect_success SYMLINKS 'deny O_RDONLY|O_CREAT for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m rdonly -c symlink-file3 &&
    test_path_is_missing file3-non-existant
'

test_expect_success 'deny O_RDONLY|O_CREAT|O_EXCL' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m rdonly -cx file4-non-existant rdonly-creat-excl &&
    test_path_is_missing file4-non-existant
'

test_expect_success 'deny O_RDONLY|O_CREAT|O_EXCL for existing file' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EEXIST -m rdonly -cx file5
'

test_expect_success SYMLINKS 'deny O_RDONLY|O_CREAT|O_EXCL for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EEXIST -m rdonly -cx symlink-file6 &&
    test_path_is_missing file6-non-existant
'

test_expect_success 'deny O_WRONLY' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m wronly file7 "3" &&
    test_path_is_empty file7
'

test_expect_success 'deny O_WRONLY for non-existant file' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e ENOENT -m wronly file8-non-existant "3" &&
    test_path_is_missing file8-non-existant
'

test_expect_success SYMLINKS 'deny O_WRONLY for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m wronly symlink-file9 "3" &&
    test_path_is_empty file9
'

test_expect_success 'deny O_WRONLY|O_CREAT' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m wronly -c file10-non-existant "3" &&
    test_path_is_missing file10-non-existant
'

test_expect_success 'deny O_WRONLY|O_CREAT for existing file' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m wronly -c file11 "3" &&
    test_path_is_empty file11
'

test_expect_success SYMLINKS 'deny O_WRONLY|O_CREAT for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m wronly -c symlink-file12 "3" &&
    test_path_is_empty file12
'

test_expect_success SYMLINKS 'deny O_WRONLY|O_CREAT for dangling symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m wronly -c symlink-file13 "3" &&
    test_path_is_missing file13-non-existant
'

test_expect_success 'deny O_WRONLY|O_CREAT|O_EXCL' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m wronly -cx file14-non-existant "3" &&
    test_path_is_missing file14-non-existant
'

test_expect_success 'deny O_WRONLY|O_CREAT|O_EXCL for existing file' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EEXIST -m wronly -cx file15 "3" &&
    test_path_is_empty file15
'

test_expect_success 'whitelist O_WRONLY' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily open -e ERRNO_0 -m wronly file16 "3" &&
    test_path_is_non_empty file16
'

test_expect_success 'whitelist O_WRONLY|O_CREAT' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily open -e ERRNO_0 -m wronly -c file17-non-existant &&
    test_path_is_file file17-non-existant
'

test_expect_success 'whitelist O_WRONLY|O_CREAT|O_EXCL' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily open -e ERRNO_0 -m wronly -cx file18-non-existant &&
    test_path_is_file file18-non-existant
'

test_expect_success 'whitelist O_WRONLY|O_CREAT|O_EXCL for existing file' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily open -e EEXIST -m wronly -cx file19
'

test_expect_success 'deny O_RDWR' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m rdwr file20 "3" &&
    test_path_is_empty file20
'

test_expect_success 'deny O_RDWR|O_CREAT' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m rdwr -c file21-non-existant &&
    test_path_is_missing file21-non-existant
'

test_expect_success 'deny O_RDWR|O_CREAT|O_EXCL' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m rdwr -cx file22-non-existant &&
    test_path_is_missing file22-non-existant
'

test_expect_success 'deny O_RDWR|O_CREAT|O_EXCL for existing file' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EEXIST -m rdwr -cx file23 "3" &&
    test_path_is_empty file23
'

test_expect_success 'whitelist O_RDWR' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily open -e ERRNO_0 -m rdwr file24 "3" &&
    test_path_is_non_empty file24
'

test_expect_success 'whitelist O_RDWR|O_CREAT' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily open -e ERRNO_0 -m rdwr -c file25-non-existant &&
    test_path_is_file file25-non-existant
'

test_expect_success 'whitelist O_RDWR|O_CREAT|O_EXCL' '
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily open -e ERRNO_0 -m rdwr -cx file26-non-existant &&
    test_path_is_file file26-non-existant
'

test_expect_success 'whitelist O_RDWR|O_CREAT|O_EXCL for existing file' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily open -e EEXIST -m rdwr -cx file27
'

test_expect_success 'blacklist O_RDONLY|O_CREAT' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m rdonly -c file28-non-existant &&
    test_path_is_missing file28-non-existant
'

test_expect_success SYMLINKS 'blacklist O_RDONLY|O_CREAT for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m rdonly -c symlink-file29 &&
    test_path_is_missing file29-non-existant
'

test_expect_success 'blacklist O_RDONLY|O_CREAT|O_EXCL' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m rdonly -cx file30-non-existant &&
    test_path_is_missing file30-non-existant
'

test_expect_success 'blacklist O_RDONLY|O_CREAT|O_EXCL for existing file' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EEXIST -m rdonly -cx file31
'

test_expect_success SYMLINKS 'blacklist O_RDONLY|O_CREAT|O_EXCL for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EEXIST -m rdonly -cx symlink-file32 &&
    test_path_is_missing file32-non-existant
'

test_expect_success 'blacklist O_WRONLY' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m wronly file33 "3" &&
    test_path_is_empty file33
'

test_expect_success 'blacklist O_WRONLY for non-existant file' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e ENOENT -m wronly file34-non-existant &&
    test_path_is_missing file34-non-existant
'

test_expect_success SYMLINKS 'blacklist O_WRONLY for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m wronly symlink-file35 "3" &&
    test_path_is_empty file35
'

test_expect_success 'blacklist O_WRONLY|O_CREAT' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m wronly -c file36-non-existant &&
    test_path_is_missing file36-non-existant
'

test_expect_success 'blacklist O_WRONLY|O_CREAT for existing file' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m wronly -c file37 "3" &&
    test_path_is_empty file37
'

test_expect_success SYMLINKS 'blacklist O_WRONLY|O_CREAT for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m wronly -c symlink-file38 "3" &&
    test_path_is_empty file38
'

test_expect_success SYMLINKS 'blacklist O_WRONLY|O_CREAT for dangling symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m wronly -c symlink-file39 "3" &&
    test_path_is_missing file39-non-existant
'

test_expect_success 'blacklist O_WRONLY|O_CREAT|O_EXCL' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m wronly -cx file40-non-existant &&
    test_path_is_missing file40-non-existant
'

test_expect_success 'blacklist O_WRONLY|O_CREAT|O_EXCL for existing file' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EEXIST -m wronly -cx file41 "3" &&
    test_path_is_empty file41
'

test_done
