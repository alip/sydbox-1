#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='sandbox openat(2)'
. ./test-lib.sh

test_expect_success setup '
    touch file1 &&
    touch file2 &&
    touch file3 &&
    touch file4 &&
    touch file10 &&
    touch file13 &&
    touch file15 &&
    touch file17 &&
    touch file18 &&
    touch file20 &&
    touch file22 &&
    touch file23 &&
    touch file26 &&
    touch file27 &&
    touch file30 &&
    touch file32 &&
    touch file33 &&
    touch file34 &&
    touch file38 &&
    touch file40 &&
    touch file41 &&
    touch file42 &&
    touch file46 &&
    touch file48 &&
    touch file49 &&
    touch file50 &&
    touch file54 &&
    touch file56 &&
    touch file62 &&
    touch file65 &&
    touch file67 &&
    touch file69 &&
    touch file70 &&
    touch file72 &&
    touch file74 &&
    touch file75 &&
    touch file78 &&
    touch file79 &&
    touch file82 &&
    touch file84
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf /non/existant/file symlink-dangling &&
    ln -sf file2 symlink-file2 &&
    ln -sf file4 symlink-file4 &&
    ln -sf file6-non-existant symlink-file6 &&
    ln -sf file8-non-existant symlink-file8 &&
    ln -sf file11-non-existant symlink-file11 &&
    ln -sf file14-non-existant symlink-file14 &&
    ln -sf file17 symlink-file17 &&
    ln -sf file20 symlink-file20 &&
    ln -sf file24-non-existant symlink-file24 &&
    ln -sf file28-non-existant symlink-file28 &&
    ln -sf file58-non-existant symlink-file58 &&
    ln -sf file60-non-existant symlink-file60 &&
    ln -sf file63-non-existant symlink-file63 &&
    ln -sf file66-non-existant symlink-file66 &&
    ln -sf file69 symlink-file69 &&
    ln -sf file72 symlink-file72 &&
    ln -sf file75 symlink-file75 &&
    ln -sf file76-non-existant symlink-file76 &&
    ln -sf file78 symlink-file78 &&
    ln -sf file80-non-existant symlink-file80
'

test_expect_success 'deny openat(AT_FDCWD, NULL) with EFAULT' '
    sydbox -- emily openat -e EFAULT -d cwd
'

test_expect_success 'deny openat(-1) with EBADF' '
    sydbox -- emily openat -e EBADF -d null -m rdonly file0-non-existant
'

test_expect_success 'whitelist openat(AT_FDCWD, $path, O_RDONLY)' '
    sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e ERRNO_0 -m rdonly -d cwd file1
'

test_expect_success SYMLINKS 'whitelist openat(AT_FDCWD, $path, O_RDONLY) for symbolic link' '
    sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e ERRNO_0 -m rdonly -d cwd symlink-file2
'

test_expect_success 'whitelist openat(fd, $path, O_RDONLY)' '
    sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e ERRNO_0 -m rdonly -d "$HOME" file3
'

test_expect_success SYMLINKS 'whitelist openat(fd, $path, O_RDONLY) for symbolic link' '
    sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e ERRNO_0 -m rdonly -d "$HOME" symlink-file4
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_RDONLY|O_CREAT)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d cwd -c file5-non-existant &&
    test_path_is_missing file5-non-existant
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_RDONLY|O_CREAT) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d cwd -c symlink-file6 &&
    test_path_is_missing file6-non-existant
'

test_expect_success 'deny openat(fd, $path, O_RDONLY|O_CREAT)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d "$HOME" -c file7-non-existant &&
    test_path_is_missing file7-non-existant
'

test_expect_success 'deny openat(fd, $path, O_RDONLY|O_CREAT) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d "$HOME" -c symlink-file8 &&
    test_path_is_missing file8-non-existant
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_RDONLY|O_CREAT|O_EXCL)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d cwd -cx file9-non-existant &&
    test_path_is_missing file9-non-existant
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_RDONLY|O_CREAT|O_EXCL) for existing file' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m rdonly -d cwd -cx file10
'

test_expect_success SYMLINKS 'deny openat(AT_FDCWD, $path, O_RDONLY|O_CREAT|O_EXCL) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m rdonly -d cwd -cx symlink-file11 &&
    test_path_is_missing file11-non-existant
'

test_expect_success 'deny openat(fd, $path, O_RDONLY|O_CREAT|O_EXCL)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d "$HOME" -cx file12-non-existant &&
    test_path_is_missing file12-non-existant
'

test_expect_success 'deny openat(fd, $path, O_RDONLY|O_CREAT|O_EXCL) for existing file' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m rdonly -d "$HOME" -cx file13
'

test_expect_success SYMLINKS 'deny openat(fd, $path, O_RDONLY|O_CREAT|O_EXCL) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m rdonly -d "$HOME" -cx symlink-file14 &&
    test_path_is_missing file14-non-existant
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_WRONLY)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d cwd file15 "3" &&
    test_path_is_empty file15
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_WRONLY) for non-existant file' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e ENOENT -m wronly -d cwd file16-non-existant "3" &&
    test_path_is_missing file16-non-existant
'

test_expect_success SYMLINKS 'deny openat(AT_FDCWD, $path, O_WRONLY) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d cwd symlink-file17 "3" &&
    test_path_is_empty file17
'

test_expect_success 'deny openat(fd, $path, O_WRONLY)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d "$HOME" file15 "3" &&
    test_path_is_empty file18
'

test_expect_success 'deny openat(fd, $path, O_WRONLY) for non-existant file' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e ENOENT -m wronly -d "$HOME" file19-non-existant "3" &&
    test_path_is_missing file19-non-existant
'

test_expect_success SYMLINKS 'deny openat(fd, $path, O_WRONLY) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d "$HOME" symlink-file20 "3" &&
    test_path_is_empty file20
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_WRONLY|O_CREAT)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d cwd -c file21-non-existant "3" &&
    test_path_is_missing file21-non-existant
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_WRONLY|O_CREAT for existing file)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d cwd -c file22 "3" &&
    test_path_is_empty file22
'

test_expect_success SYMLINKS 'deny openat(AT_FDCWD, $path, O_WRONLY|O_CREAT) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d cwd -c symlink-file23 "3" &&
    test_path_is_empty file23
'

test_expect_success SYMLINKS 'deny openat(AT_FDCWD, $path, O_WRONLY|O_CREAT) for dangling symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d cwd -c symlink-file24 "3" &&
    test_path_is_missing file24-non-existant
'

test_expect_success 'deny openat(fd, $path, O_WRONLY|O_CREAT)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c file25-non-existant "3" &&
    test_path_is_missing file25-non-existant
'

test_expect_success 'deny openat(fd, $path, O_WRONLY|O_CREAT for existing file)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c file26 "3" &&
    test_path_is_empty file26
'

test_expect_success SYMLINKS 'deny openat(fd, $path, O_WRONLY|O_CREAT) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c symlink-file27 "3" &&
    test_path_is_empty file27
'

test_expect_success SYMLINKS 'deny openat(fd, $path, O_WRONLY|O_CREAT) for dangling symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c symlink-file28 "3" &&
    test_path_is_missing file28-non-existant
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_WRONLY|O_CREAT|O_EXCL)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d cwd -cx file29-non-existant "3" &&
    test_path_is_missing file29-non-existant
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_WRONLY|O_CREAT|O_EXCL) for existing file' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m wronly -d cwd -cx file30 "3" &&
    test_path_is_empty file30
'

test_expect_success 'deny openat(fd, $path, O_WRONLY|O_CREAT|O_EXCL)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d "$HOME" -cx file31-non-existant "3" &&
    test_path_is_missing file31-non-existant
'

test_expect_success 'deny openat(fd, $path, O_WRONLY|O_CREAT|O_EXCL) for existing file' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m wronly -d "$HOME" -cx file32 "3" &&
    test_path_is_empty file32
'

test_expect_success 'whitelist openat(AT_FDCWD, $path, O_WRONLY)' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d cwd file33 "3" &&
    test_path_is_non_empty file33
'

test_expect_success 'whitelist openat(fd, $path, O_WRONLY)' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d "$HOME" file34 "3" &&
    test_path_is_non_empty file34
'

test_expect_success 'whitelist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT)' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d cwd -c file35-non-existant &&
    test_path_is_file file35-non-existant
'

test_expect_success 'whitelist openat(fd, $path, O_WRONLY|O_CREAT)' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d "$HOME" -c file36-non-existant &&
    test_path_is_file file36-non-existant
'

test_expect_success 'whitelist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT|O_EXCL)' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d cwd -cx file37-non-existant &&
    test_path_is_file file37-non-existant
'

test_expect_success 'whitelist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT|O_EXCL) for existing file' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m wronly -d cwd -cx file38
'

test_expect_success 'whitelist openat(fd, $path, O_WRONLY|O_CREAT|O_EXCL)' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d "$HOME" -cx file39-non-existant &&
    test_path_is_file file39-non-existant
'

test_expect_success 'whitelist openat(fd, $path, O_WRONLY|O_CREAT|O_EXCL) for existing file' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m wronly -d "$HOME" -cx file40
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_RDWR)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d cwd file41 "3" &&
    test_path_is_empty file41
'

test_expect_success 'deny openat(fd, $path, O_RDWR)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d "$HOME" file42 "3" &&
    test_path_is_empty file42
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_RDWR|O_CREAT)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d cwd -c file43-non-existant &&
    test_path_is_missing file43-non-existant
'

test_expect_success 'deny openat(fd, $path, O_RDWR|O_CREAT)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d "$HOME" -c file44-non-existant &&
    test_path_is_missing file44-non-existant
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_RDWR|O_CREAT|O_EXCL)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d cwd -cx file45-non-existant &&
    test_path_is_missing file45-non-existant
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_RDWR|O_CREAT|O_EXCL) for existing file' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m rdwr -d cwd -cx file46 "3" &&
    test_path_is_empty file46
'

test_expect_success 'deny openat(fd, $path, O_RDWR|O_CREAT|O_EXCL)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d "$HOME" -cx file47-non-existant &&
    test_path_is_missing file47-non-existant
'

test_expect_success 'deny openat(fd, $path, O_RDWR|O_CREAT|O_EXCL) for existing file' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m rdwr -d "$HOME" -cx file48 "3" &&
    test_path_is_empty file48
'

test_expect_success 'whitelist openat(AT_FDCWD, $path, O_RDWR)' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d cwd file49 "3" &&
    test_path_is_non_empty file49
'

test_expect_success 'whitelist openat(fd, $path, O_RDWR)' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d "$HOME" file50 "3" &&
    test_path_is_non_empty file50
'

test_expect_success 'whitelist openat(AT_FDCWD, $path, O_RDWR|O_CREAT)' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d cwd -c file51-non-existant &&
    test_path_is_file file51-non-existant
'

test_expect_success 'whitelist openat(fd, $path, O_RDWR|O_CREAT)' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d "$HOME" -c file52-non-existant &&
    test_path_is_file file52-non-existant
'

test_expect_success 'whitelist openat(AT_FDCWD, $path, O_RDWR|O_CREAT|O_EXCL)' '
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d cwd -cx file53-non-existant &&
    test_path_is_file file53-non-existant
'

test_expect_success 'whitelist openat(AT_FDCWD, $path, O_RDWR|O_CREAT|O_EXCL) for existing file' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m rdwr -d cwd -cx file54
'

test_expect_success 'whitelist openat(fd, $path, O_RDWR|O_CREAT|O_EXCL)' '
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d "$HOME" -cx file55-non-existant &&
    test_path_is_file file55-non-existant
'

test_expect_success 'whitelist openat(fd, $path, O_RDWR|O_CREAT|O_EXCL) for existing file' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m rdwr -d "$HOME" -cx file56
'

test_expect_success 'blacklist openat(AT_FDCWD, $path, O_RDONLY|O_CREAT)' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m rdonly -d cwd -c file57-non-existant &&
    test_path_is_missing file57-non-existant
'

test_expect_success SYMLINKS 'blacklist openat(AT_FDCWD, $path, O_RDONLY|O_CREAT) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m rdonly -d cwd -c symlink-file58 &&
    test_path_is_missing file58-non-existant
'

test_expect_success 'blacklist openat(fd, $path, O_RDONLY|O_CREAT)' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m rdonly -d "$HOME" -c file59-non-existant &&
    test_path_is_missing file59-non-existant
'

test_expect_success SYMLINKS 'blacklist openat(fd, $path, O_RDONLY|O_CREAT) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m rdonly -d "$HOME" -c symlink-file60 &&
    test_path_is_missing file60-non-existant
'

test_expect_success 'blacklist openat(AT_FDCWD, $path, O_RDONLY|O_CREAT|O_EXCL)' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m rdonly -d cwd -cx file61-non-existant &&
    test_path_is_missing file61-non-existant
'

test_expect_success 'blacklist openat(AT_FDCWD, $path, O_RDONLY|O_CREAT|O_EXCL) for existing file' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m rdonly -d cwd -cx file62
'

test_expect_success SYMLINKS 'blacklist openat(AT_FDCWD, $path, O_RDONLY|O_CREAT|O_EXCL) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m rdonly -d cwd -cx symlink-file63 &&
    test_path_is_missing file63-non-existant
'

test_expect_success 'blacklist openat(fd, $path, O_RDONLY|O_CREAT|O_EXCL)' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m rdonly -d "$HOME" -cx file614-non-existant &&
    test_path_is_missing file64-non-existant
'

test_expect_success 'blacklist openat(fd, $path, O_RDONLY|O_CREAT|O_EXCL) for existing file' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m rdonly -d "$HOME" -cx file65
'

test_expect_success SYMLINKS 'blacklist openat(fd, $path, O_RDONLY|O_CREAT|O_EXCL) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m rdonly -d "$HOME" -cx symlink-file66 &&
    test_path_is_missing file66-non-existant
'

test_expect_success 'blacklist openat(AT_FDCWD, $path, O_WRONLY)' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d cwd file67 "3" &&
    test_path_is_empty file67
'

test_expect_success 'blacklist openat(AT_FDCWD, $path, O_WRONLY) for non-existant file' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ENOENT -m wronly -d cwd file68-non-existant &&
    test_path_is_missing file68-non-existant
'

test_expect_success SYMLINKS 'blacklist openat(AT_FDCWD, $path, O_WRONLY) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d cwd symlink-file69 "3" &&
    test_path_is_empty file69
'

test_expect_success 'blacklist openat(fd, $path, O_WRONLY)' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d "$HOME" file70 "3" &&
    test_path_is_empty file70
'

test_expect_success 'blacklist openat(fd, $path, O_WRONLY) for non-existant file' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ENOENT -m wronly -d "$HOME" file71-non-existant &&
    test_path_is_missing file71-non-existant
'

test_expect_success SYMLINKS 'blacklist openat(fd, $path, O_WRONLY) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d "$HOME" symlink-file72 "3" &&
    test_path_is_empty file72
'

test_expect_success 'blacklist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT)' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d cwd -c file73-non-existant &&
    test_path_is_missing file73-non-existant
'

test_expect_success 'blacklist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT) for existing file' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d cwd -c file74 "3" &&
    test_path_is_empty file74
'

test_expect_success SYMLINKS 'blacklist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d cwd -c symlink-file75 "3" &&
    test_path_is_empty file75
'

test_expect_success SYMLINKS 'blacklist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT) for dangling symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d cwd -c symlink-file76 "3" &&
    test_path_is_missing file76-non-existant
'

test_expect_success 'blacklist openat(fd, $path, O_WRONLY|O_CREAT)' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c file77-non-existant &&
    test_path_is_missing file77-non-existant
'

test_expect_success 'blacklist openat(fd, $path, O_WRONLY|O_CREAT) for existing file' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c file78 "3" &&
    test_path_is_empty file78
'

test_expect_success SYMLINKS 'blacklist openat(fd, $path, O_WRONLY|O_CREAT) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c symlink-file79 "3" &&
    test_path_is_empty file79
'

test_expect_success SYMLINKS 'blacklist openat(fd, $path, O_WRONLY|O_CREAT) for dangling symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c symlink-file80 "3" &&
    test_path_is_missing file80-non-existant
'

test_expect_success 'blacklist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT|O_EXCL)' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d cwd -cx file81-non-existant &&
    test_path_is_missing file81-non-existant
'

test_expect_success 'blacklist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT|O_EXCL) for existing file' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m wronly -d cwd -cx file82 "3" &&
    test_path_is_empty file82
'

test_expect_success 'blacklist openat(fd, $path, O_WRONLY|O_CREAT|O_EXCL)' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d "$HOME" -cx file83-non-existant &&
    test_path_is_missing file83-non-existant
'

test_expect_success 'blacklist openat(fd, $path, O_WRONLY|O_CREAT|O_EXCL) for existing file' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m wronly -d "$HOME" -cx file84 "3" &&
    test_path_is_empty file84
'

test_done
