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
    touch file27
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf /non/existant/file symlink-dangling &&
    ln -sf file1 symlink-file1 &&
    ln -sf file3-non-existant symlink-file3 &&
    ln -sf file6-non-existant symlink-file6 &&
    ln -sf file9 symlink-file9 &&
    ln -sf file12 symlink-file12 &&
    ln -sf file13-non-existant symlink-file13
'

test_expect_success 'deny open(NULL) with EFAULT' '
    sydbox -ESYDBOX_TEST_EFAULT=1 -- emily open
'

test_expect_success 'allow O_RDONLY' '
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -- emily open file0 rdonly
'

test_expect_success SYMLINKS 'allow O_RDONLY for symbolic link' '
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -- emily open symlink-file1 rdonly
'

test_expect_success 'deny O_RDONLY|O_CREAT' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily open file2-non-existant rdonly-creat &&
    test_path_is_missing file2-non-existant
'

test_expect_success SYMLINKS 'deny O_RDONLY|O_CREAT for symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily open symlink-file3 rdonly-creat &&
    test_path_is_missing file3-non-existant
'

test_expect_success 'deny O_RDONLY|O_CREAT|O_EXCL' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily open file4-non-existant rdonly-creat-excl &&
    test_path_is_missing file4-non-existant
'

test_expect_success 'deny O_RDONLY|O_CREAT|O_EXCL for existing file' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EEXIST=1 \
        -m core/sandbox/write:deny \
        -- emily open file5 rdonly-creat-excl
'

test_expect_success SYMLINKS 'deny O_RDONLY|O_CREAT|O_EXCL for symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EEXIST=1 \
        -m core/sandbox/write:deny \
        -- emily open symlink-file6 rdonly-creat-excl &&
    test_path_is_missing file6-non-existant
'

test_expect_success 'deny O_WRONLY' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily open file7 wronly "3" &&
    test_path_is_empty file7
'

test_expect_success 'deny O_WRONLY for non-existant file' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily open file8-non-existant wronly &&
    test_path_is_missing file8-non-existant
'

test_expect_success SYMLINKS 'deny O_WRONLY for symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily open symlink-file9 wronly "3" &&
    test_path_is_empty file9
'

test_expect_success 'deny O_WRONLY|O_CREAT' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily open file10-non-existant wronly-creat &&
    test_path_is_missing file10-non-existant
'

test_expect_success 'deny O_WRONLY|O_CREAT for existing file' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily open file11 wronly-creat "3" &&
    test_path_is_empty file11
'

test_expect_success SYMLINKS 'deny O_WRONLY|O_CREAT for symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily open symlink-file12 wronly-creat "3" &&
    test_path_is_empty file12
'

test_expect_success SYMLINKS 'deny O_WRONLY|O_CREAT for dangling symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily open symlink-file13 wronly-creat "3" &&
    test_path_is_missing file13-non-existant
'

test_expect_success 'deny O_WRONLY|O_CREAT|O_EXCL' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily open file14-non-existant wronly-creat-excl &&
    test_path_is_missing file14-non-existant
'

test_expect_success 'deny O_WRONLY|O_CREAT|O_EXCL for existing file' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EEXIST=1 \
        -m core/sandbox/write:deny \
        -- emily open file15 wronly-creat-excl "3" &&
    test_path_is_empty file15
'

test_expect_success 'allow O_WRONLY' '
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/*" \
        -- emily open file16 wronly "3" &&
    test_path_is_non_empty file16
'

test_expect_success 'allow O_WRONLY|O_CREAT' '
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/*" \
        -- emily open file17-non-existant wronly-creat &&
    test_path_is_file file17-non-existant
'

test_expect_success 'allow O_WRONLY|O_CREAT|O_EXCL' '
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/*" \
        -- emily open file18-non-existant wronly-creat-excl &&
    test_path_is_file file18-non-existant
'

test_expect_success 'allow O_WRONLY|O_CREAT|O_EXCL for existing file' '
    sydbox \
        -ESYDBOX_TEST_EEXIST=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/*" \
        -- emily open file19 wronly-creat-excl
'

test_expect_success 'deny O_RDWR' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily open file20 rdwr "3" &&
    test_path_is_empty file20
'

test_expect_success 'deny O_RDWR|O_CREAT' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily open file21-non-existant rdwr-creat &&
    test_path_is_missing file21-non-existant
'

test_expect_success 'deny O_RDWR|O_CREAT|O_EXCL' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily open file22-non-existant rdwr-creat-excl &&
    test_path_is_missing file22-non-existant
'

test_expect_success 'deny O_RDWR|O_CREAT|O_EXCL for existing file' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EEXIST=1 \
        -m core/sandbox/write:deny \
        -- emily open file23 rdwr-creat-excl "3" &&
    test_path_is_empty file23
'

test_expect_success 'allow O_RDWR' '
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/*" \
        -- emily open file24 rdwr "3" &&
    test_path_is_non_empty file24
'

test_expect_success 'allow O_RDWR|O_CREAT' '
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/*" \
        -- emily open file25-non-existant rdwr-creat &&
    test_path_is_file file25-non-existant
'

test_expect_success 'allow O_RDWR|O_CREAT|O_EXCL' '
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/*" \
        -- emily open file26-non-existant rdwr-creat-excl &&
    test_path_is_file file26-non-existant
'

test_expect_success 'allow O_RDWR|O_CREAT|O_EXCL for existing file' '
    sydbox \
        -ESYDBOX_TEST_EEXIST=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/*" \
        -- emily open file27 rdwr-creat-excl
'

test_done
