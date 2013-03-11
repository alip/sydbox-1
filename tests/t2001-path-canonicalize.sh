#!/bin/sh
# Copyright 2012, 2013 Ali Polatel <alip@exherbo.org>
# Released under the terms of the 3-clause BSD license

test_description='test pathname canonicalization'
. ./test-lib.sh

statinode() {
	case "$(uname -s)" in
	Linux)
		stat -c '%i' "$@"
		;;
	Darwin)
		stat -f '%i' "$@"
		;;
	FreeBSD)
		stat -f '%i' "$@"
		;;
	*)
		ls -di "$@" | cut -d ' ' -f 1
		;;
	esac
}

test_expect_success SYMLINKS setup-symlinks '
    ln -sf self self &&
    ln -sf loop0 loop1 &&
    ln -sf loop1 loop0
'

test_expect_success 'canonicalize MULTIPLE_BITS_SET -> EINVAL' '
    canontest -e EINVAL -m existing -m all_but_last -m missing /foo
'

test_expect_success 'canonicalize non-absolute path -> EINVAL' '
    canontest -e EINVAL -m existing foo
'

test_expect_success 'canonicalize empty path -> ENOENT' '
    canontest -e ENOENT -m existing ""
'

test_expect_success 'canontest -r works' '
    f="$(unique_file)"
    : > "$f" &&
    canontest -r "$f" >/dev/null
'

TRASH_DIRECTORY_R=$(canontest -r "$TRASH_DIRECTORY")
export TRASH_DIRECTORY_R

test_expect_success 'canonicalize ., .., intermediate // handling' '
    f="$(unique_file)" &&
    :> "$f" &&
    canontest -c -m existing "$TRASH_DIRECTORY_R//./..//$f"
'

test_expect_success 'canonicalize non-directory with trailing slash yields NULL' '
    f="$(unique_file)" &&
    :> "$f" &&
    canontest -e ENOTDIR -m existing "$TRASH_DIRECTORY_R/$f/"
'

test_expect_success 'canonicalize missing directory yields NULL' '
    d="$(unique_dir)" &&
    canontest -e ENOENT -m existing "$TRASH_DIRECTORY_R/$d/.."
'

test_expect_success SYMLINKS 'canonicalize: symlinks not resolved with CAN_NOLINKS' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    :> "$f" &&
    ln -sf "$f" "$l" &&
    canontest -m nolinks "$TRASH_DIRECTORY_R/"$l"" > out &&
    grep -q "$l" out
'

test_expect_success SYMLINKS 'canonicalize: symlinks to a file can be resolved' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    :> "$f" &&
    ln -sf "$f" "$l" &&
    canontest -m existing "$TRASH_DIRECTORY_R/"$l"" > out &&
    grep -q "$f" out
'

test_expect_success SYMLINKS 'canonicalize: symlinks to a directory can be resolved' '
    d="$(unique_dir)" &&
    l0="$(unique_link)" && l1="$(unique_link)" && l2="$(unique_link)" &&
    mkdir "$d" &&
    ln -sf "$d" "$l0" &&
    ln -sf "$l0" "$l1" &&
    ln -sf "$l1" "$l2" &&
    canontest -m existing "$TRASH_DIRECTORY_R/$d" > exp &&
    canontest -m existing "$TRASH_DIRECTORY_R/$l0" > out0 &&
    canontest -m existing "$TRASH_DIRECTORY_R/$l1" > out1 &&
    canontest -m existing "$TRASH_DIRECTORY_R/$l2" > out2 &&
    test_cmp exp out0 &&
    test_cmp exp out1 &&
    test_cmp exp out2
'

test_expect_success SYMLINKS 'canonicalize: symlink to a non-existing file yields NULL' '
    f="no-$(unique_file)"
    l="$(unique_link)"
    rm -f "$f" &&
    ln -sf "$f" "$l" &&
    canontest -e ENOENT -m existing "$TRASH_DIRECTORY_R/$l"
'

test_expect_success SYMLINKS 'canonicalize: non-directory symlink with a trailing slash yields NULL' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    : > "$f" &&
    ln -sf "$f" "$l" &&
    canontest -e ENOTDIR -m existing "$TRASH_DIRECTORY_R/"$l"/"
'

test_expect_success SYMLINKS 'canonicalize: missing directory via symlink yields NULL' '
    d="$(unique_dir)" &&
    l="$(unique_link)" &&
    rm -rf "$d" &&
    ln -sf "$d" "$l" &&
    canontest -e ENOENT -m existing "$TRASH_DIRECTORY_R/$l/.."
'

test_expect_success SYMLINKS 'canonicalize: loop of symlinks are detected' '
    canontest -e ELOOP -m existing "$TRASH_DIRECTORY_R/loop1"
'

test_expect_success 'canonicalize: alternate modes can resolve basenames' '
    f="no-$(unique_file)" &&
    rm -f "$f" &&
    canontest -m all_but_last "$TRASH_DIRECTORY_R/"$f"" > out0 &&
    grep -q "$f" out0 &&
    canontest -m missing "$TRASH_DIRECTORY_R/"$f"" > out1 &&
    grep -q "$f" out1 &&
    canontest -m all_but_last "$TRASH_DIRECTORY/"$f"/" > out2 &&
    grep -q "$f" out2 &&
    canontest -m missing "$TRASH_DIRECTORY/"$f"/" > out3 &&
    grep -q "$f" out3
'

test_expect_success SYMLINKS 'canonicalize: alternate modes can resolve symlink basenames' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    rm -f "$f" &&
    ln -sf "$f" "$l" &&
    canontest -m all_but_last "$TRASH_DIRECTORY_R/"$l"" > out0 &&
    grep -q "$f" out0 &&
    canontest -m missing "$TRASH_DIRECTORY_R/"$l"" > out1 &&
    grep -q "$f" out1 &&
    canontest -m all_but_last "$TRASH_DIRECTORY/"$l"/" > out2 &&
    grep -q "$f" out2 &&
    canontest -m missing "$TRASH_DIRECTORY/"$l"/" > out3 &&
    grep -q "$f" out3
'

test_expect_success 'canonicalize: alternate modes can handle missing dirnames' '
    d="no-$(unique_dir)" &&
    rm -fr no"$d" &&
    canontest -e ENOENT -m all_but_last "$TRASH_DIRECTORY_R/$d/nofile" &&
    canontest -m missing "$TRASH_DIRECTORY_R/$d/nofile" > out &&
    grep -q "$d"/nofile out
'

# s -> link0
# p -> link1
# d/2 -> file0
# d/1 -> link3
test_expect_success SYMLINKS 'canonicalize: recent loop bug (before 2007-09-27)' '
    d="$(unique_dir)"
    f="$(unique_file)"
    l0="l0-$(unique_link)" && l1="l1-$(unique_link)" && l3="l3-$(unique_link)" &&
    mkdir "$d" &&
    ln -sf "$d" "$l0" &&
    ln -sf "$l0" "$l1" &&
    : > "$d"/"$f" &&
    ln -sf ../"$l0"/"$f" "$d"/"$l3" &&
    canontest -m existing "$TRASH_DIRECTORY_R" > expected &&
    printf "/$d/$f" >> expected &&
    canontest -m existing "$TRASH_DIRECTORY_R/$l1/$l3" > result &&
    test_cmp expected result
'

test_expect_success 'canonicalize: leading // is honoured correctly' '
    l0="$(unique_link)"
    ln -sf //.//../.. $l0 &&
    statinode / > inode0 &&
    statinode // > inode1 &&
    canontest -m existing -r //. > result1 &&
    canontest -m existing //. > result2 &&
    canontest -m existing -r "$TRASH_DIRECTORY_R/$l0" > result3 &&
    canontest -m existing "$TRASH_DIRECTORY_R/$l0" > result4 &&
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
