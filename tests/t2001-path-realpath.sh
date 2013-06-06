#!/bin/sh
# Copyright 2012, 2013 Ali Polatel <alip@exherbo.org>
# Released under the terms of the 3-clause BSD license

test_description='test pathname canonicalization'
. ./test-lib.sh

test_expect_success SYMLINKS setup-symlinks '
    ln -sf self self &&
    ln -sf loop0 loop1 &&
    ln -sf loop1 loop0
'

test_expect_success 'realpath: non-absolute path -> EINVAL' '
    realpath-test -e EINVAL -m exist foo
'

test_expect_success 'realpath: empty path -> ENOENT' '
    realpath-test -e ENOENT -m exist ""
'

test_expect_success 'realpath-test -r works' '
    f="$(unique_file)"
    : > "$f" &&
    realpath-test -r "$f" >/dev/null
'

TRASH_DIRECTORY_R=$(realpath-test -r "$TRASH_DIRECTORY")
export TRASH_DIRECTORY_R

test_expect_success 'realpath ., .., intermediate // handling' '
    f="$(unique_file)" &&
    :> "$f" &&
    realpath-test -c -m exist "$TRASH_DIRECTORY_R//./..//$f"
'

test_expect_success 'realpath non-directory with trailing slash yields NULL' '
    f="$(unique_file)" &&
    :> "$f" &&
    realpath-test -e ENOTDIR -m exist "$TRASH_DIRECTORY_R/$f/"
'

test_expect_success 'realpath missing directory yields NULL' '
    d="$(unique_dir)" &&
    realpath-test -e ENOENT -m exist "$TRASH_DIRECTORY_R/$d/.."
'

test_expect_success SYMLINKS 'realpath: symlinks not resolved with RPATH_NOFOLLOW' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    :> "$f" &&
    ln -sf "$f" "$l" &&
    realpath-test -m nofollow "$TRASH_DIRECTORY_R/"$l"" > out &&
    grep -q "$l" out
'

test_expect_success SYMLINKS 'realpath: symlinks to a file can be resolved' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    :> "$f" &&
    ln -sf "$f" "$l" &&
    realpath-test -m exist "$TRASH_DIRECTORY_R/"$l"" > out &&
    grep -q "$f" out
'

test_expect_success SYMLINKS 'realpath: symlinks to a directory can be resolved' '
    d="$(unique_dir)" &&
    l0="$(unique_link)" && l1="$(unique_link)" && l2="$(unique_link)" &&
    mkdir "$d" &&
    ln -sf "$d" "$l0" &&
    ln -sf "$l0" "$l1" &&
    ln -sf "$l1" "$l2" &&
    realpath-test -m exist "$TRASH_DIRECTORY_R/$d" > exp &&
    realpath-test -m exist "$TRASH_DIRECTORY_R/$l0" > out0 &&
    realpath-test -m exist "$TRASH_DIRECTORY_R/$l1" > out1 &&
    realpath-test -m exist "$TRASH_DIRECTORY_R/$l2" > out2 &&
    test_cmp exp out0 &&
    test_cmp exp out1 &&
    test_cmp exp out2
'

test_expect_success SYMLINKS 'realpath: symlink to a non-existing file yields NULL' '
    f="no-$(unique_file)"
    l="$(unique_link)"
    rm -f "$f" &&
    ln -sf "$f" "$l" &&
    realpath-test -e ENOENT -m exist "$TRASH_DIRECTORY_R/$l"
'

test_expect_success SYMLINKS 'realpath: non-directory symlink with a trailing slash yields NULL' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    : > "$f" &&
    ln -sf "$f" "$l" &&
    realpath-test -e ENOTDIR -m exist "$TRASH_DIRECTORY_R/"$l"/"
'

test_expect_success SYMLINKS 'realpath: missing directory via symlink yields NULL' '
    d="$(unique_dir)" &&
    l="$(unique_link)" &&
    rm -rf "$d" &&
    ln -sf "$d" "$l" &&
    realpath-test -e ENOENT -m exist "$TRASH_DIRECTORY_R/$l/.."
'

test_expect_success SYMLINKS 'realpath: loop of symlinks are detected' '
    realpath-test -e ELOOP -m exist "$TRASH_DIRECTORY_R/loop1"
'

test_expect_success 'realpath: alternate modes can resolve basenames' '
    f="no-$(unique_file)" &&
    rm -f "$f" &&
    realpath-test -m nolast "$TRASH_DIRECTORY_R/"$f"" > out0 &&
    grep -q "$f" out0 &&
    realpath-test -m nolast "$TRASH_DIRECTORY/"$f"/" > out1 &&
    grep -q "$f" out1
'

test_expect_success SYMLINKS 'realpath: alternate modes can resolve symlink basenames' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    rm -f "$f" &&
    ln -sf "$f" "$l" &&
    realpath-test -m nolast "$TRASH_DIRECTORY_R/"$l"" > out0 &&
    grep -q "$f" out0 &&
    realpath-test -m nolast "$TRASH_DIRECTORY/"$l"/" > out1 &&
    grep -q "$f" out1
'

test_expect_success 'realpath: alternate modes can handle missing dirnames' '
    d="no-$(unique_dir)" &&
    rm -fr no"$d" &&
    realpath-test -e ENOENT -m nolast "$TRASH_DIRECTORY_R/$d/nofile"
'

# s -> link0
# p -> link1
# d/2 -> file0
# d/1 -> link3
test_expect_success SYMLINKS 'realpath: possible loop bug' '
    d="$(unique_dir)"
    f="$(unique_file)"
    l0="l0-$(unique_link)" && l1="l1-$(unique_link)" && l3="l3-$(unique_link)" &&
    mkdir "$d" &&
    ln -sf "$d" "$l0" &&
    ln -sf "$l0" "$l1" &&
    : > "$d"/"$f" &&
    ln -sf ../"$l0"/"$f" "$d"/"$l3" &&
    realpath-test -m exist "$TRASH_DIRECTORY_R" > expected &&
    printf "/$d/$f" >> expected &&
    realpath-test -m exist "$TRASH_DIRECTORY_R/$l1/$l3" > result &&
    test_cmp expected result
'

test_expect_success 'realpath: leading // is honoured correctly' '
    l0="$(unique_link)"
    ln -sf //.//../.. $l0 &&
    stat_inode / > inode0 &&
    stat_inode // > inode1 &&
    realpath-test -m exist -r //. > result1 &&
    realpath-test -m exist //. > result2 &&
    realpath-test -m exist -r "$TRASH_DIRECTORY_R/$l0" > result3 &&
    realpath-test -m exist "$TRASH_DIRECTORY_R/$l0" > result4 &&
    printf / > expected0 &&
    printf // > expected1 &&
    if test_cmp inode0 inode1
    then
        test_cmp expected0 result1 &&
        test_cmp expected0 result2 &&
        test_cmp expected0 result3 &&
        test_cmp expected0 result4
    else
        test_cmp expected1 result1 &&
        test_cmp expected1 result2 &&
        test_cmp expected1 result3 &&
        test_cmp expected1 result4
    fi
'

test_expect_success SYMLINKS 'realpath: non existing file under directory symlink' '
    d0=d0-"$(unique_dir)" &&
    d1=d1-"$(unique_dir)" &&
    f=no-"$(unique_file)" &&
    l="$(unique_link)" &&
    mkdir "$d0" && mkdir "$d1" &&
    ln -sf "../$d0" "$d1/$l" &&
    realpath-test -m nolast -m nofollow -e ERRNO_0 "$TRASH_DIRECTORY_R/$d1/$l/$f"
'

#test_expect_success SYMLINKS 'deny stat($self-symlink) with ELOOP' '
#    sydbox -- emily stat -e ELOOP self
#'
#
#test_expect_success SYMLINKS 'deny stat($circular-symlink) with ELOOP' '
#    sydbox -- emily stat -e ELOOP loop0
#'
#
#test_expect_success SYMLINKS 'deny stat(${circular-symlink}/foo) with ELOOP' '
#    sydbox -- emily stat -e ELOOP loop0/foo
#'
#
#test_expect_success SYMLINKS 'allow lstat($circular-symlink)' '
#    sydbox -- emily stat -e ERRNO_0 -n loop0
#'
#
#test_expect_success SYMLINKS 'deny lstat(${circular-symlink}/foo) with ELOOP' '
#    sydbox -- emily stat -e ELOOP -n loop0/foo
#'

test_done
