#!/bin/sh
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Based in part upon git's t0000-basic.sh which is:
#   Copyright (c) 2005 Junio C Hamano
# Distributed under the terms of the GNU General Public License v3 or later

test_description='test the very basics'
. ./test-lib.sh

# Test harness
test_expect_success 'success is reported like this' '
	:
'
test_expect_failure 'pretend we have a known breakage' '
	false
'

test_expect_success 'pretend we have fixed a known breakage (run in sub test-lib)' "
	mkdir passing-todo &&
	(cd passing-todo &&
	cat >passing-todo.sh <<-EOF &&
	#!$SHELL_PATH

	test_description='A passing TODO test

	This is run in a sub test-lib so that we do not get incorrect
	passing metrics
	'

	# Point to the t/test-lib.sh, which isn't in ../ as usual
	TEST_DIRECTORY=\"$TEST_DIRECTORY\"
	. \"\$TEST_DIRECTORY\"/test-lib.sh

	test_expect_failure 'pretend we have fixed a known breakage' '
		:
	'

	test_done
	EOF
	chmod +x passing-todo.sh &&
	./passing-todo.sh >out 2>err &&
	! test -s err &&
	sed -e 's/^> //' >expect <<-\\EOF &&
	> ok 1 - pretend we have fixed a known breakage # TODO known breakage
	> # fixed 1 known breakage(s)
	> # passed all 1 test(s)
	> 1..1
	EOF
	test_cmp expect out)
"
test_set_prereq HAVEIT
haveit=no
test_expect_success HAVEIT 'test runs if prerequisite is satisfied' '
	test_have_prereq HAVEIT &&
	haveit=yes
'
donthaveit=yes
test_expect_success DONTHAVEIT 'unmet prerequisite causes test to be skipped' '
	donthaveit=no
'
if test $haveit$donthaveit != yesyes
then
	say "bug in test framework: prerequisite tags do not work reliably"
	exit 1
fi

test_set_prereq HAVETHIS
haveit=no
test_expect_success HAVETHIS,HAVEIT 'test runs if prerequisites are satisfied' '
	test_have_prereq HAVEIT &&
	test_have_prereq HAVETHIS &&
	haveit=yes
'
donthaveit=yes
test_expect_success HAVEIT,DONTHAVEIT 'unmet prerequisites causes test to be skipped' '
	donthaveit=no
'
donthaveiteither=yes
test_expect_success DONTHAVEIT,HAVEIT 'unmet prerequisites causes test to be skipped' '
	donthaveiteither=no
'
if test $haveit$donthaveit$donthaveiteither != yesyesyes
then
	say "bug in test framework: multiple prerequisite tags do not work reliably"
	exit 1
fi

clean=no
test_expect_success 'tests clean up after themselves' '
	test_when_finished clean=yes
'

if test $clean != yes
then
	say "bug in test framework: basic cleanup command does not work reliably"
	exit 1
fi

test_expect_success 'tests clean up even on failures' "
	mkdir failing-cleanup &&
	(
	cd failing-cleanup &&

	cat >failing-cleanup.sh <<-EOF &&
	#!$SHELL_PATH

	test_description='Failing tests with cleanup commands'

	# Point to the t/test-lib.sh, which isn't in ../ as usual
	TEST_DIRECTORY=\"$TEST_DIRECTORY\"
	. \"\$TEST_DIRECTORY\"/test-lib.sh

	test_expect_success 'tests clean up even after a failure' '
		touch clean-after-failure &&
		test_when_finished rm clean-after-failure &&
		(exit 1)
	'
	test_expect_success 'failure to clean up causes the test to fail' '
		test_when_finished \"(exit 2)\"
	'
	test_done

	EOF

	chmod +x failing-cleanup.sh &&
	test_must_fail ./failing-cleanup.sh >out 2>err &&
	! test -s err &&
	! test -f \"trash directory.failing-cleanup/clean-after-failure\" &&
	sed -e 's/Z$//' -e 's/^> //' >expect <<-\\EOF &&
	> not ok - 1 tests clean up even after a failure
	> #	Z
	> #	touch clean-after-failure &&
	> #	test_when_finished rm clean-after-failure &&
	> #	(exit 1)
	> #	Z
	> not ok - 2 failure to clean up causes the test to fail
	> #	Z
	> #	test_when_finished \"(exit 2)\"
	> #	Z
	> # failed 2 among 2 test(s)
	> 1..2
	EOF
	test_cmp expect out
	)
"

################################################################
# Basics of the basics

test_expect_success 'return success if child returns success' '
    sydbox -- "$SHELL_PATH" -c "exit 0"
'

test_expect_success 'return error if child returns error' '
    sydbox -- "$SHELL_PATH" -c "exit 1"
    test $? -eq 1
'

test_expect_success 'compatible long options with sydbox-0' '
    sydbox --help &&
    sydbox --version &&
    sydfmt --help &&
    sydfmt --version
'

test_expect_success 'magic /dev/sydbox API is 1' '
    sydbox -- "$SHELL_PATH" -c "test -e /dev/sydbox" &&
    sydbox -- "$SHELL_PATH" -c "test -e /dev/sydbox/1" &&
    sydbox -- "$SHELL_PATH" -c "test -e /dev/sydbox/0 || exit 0"
'

test_expect_success 'magic /dev/sydbox boolean checking works' '
    sydbox -- "$SHELL_PATH" && <<EOF
test -e /dev/sydbox/core/sandbox/write"?"
test $? -eq 1 && exit 0
EOF
    sydbox -- "$SHELL_PATH" <<EOF
test -e /dev/sydbox/core/sandbox/write:deny &&
test -e /dev/sydbox/core/sandbox/write"?"
EOF
'

test_expect_success 'magic /dev/sydbox boolean checking works with -m switch' '
    sydbox -m core/sandbox/write:deny -- "$SHELL_PATH" <<EOF
test -e /dev/sydbox/core/sandbox/write"?"
EOF
'

test_expect_success 'magic core/violation/exit_code:0 works' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- "$SHELL_PATH" && <<EOF
: > nofile.$test_count
EOF
    test_path_is_missing nofile.$test_count
'

test_expect_success 'magic core/violation/raise_fail:1 works' '
    mkdir dir.$test_count &&
    test_must_violate sydbox \
        -m core/violation/raise_fail:1 \
        -- "$SHELL_PATH" && <<EOF
: > dir.$test_count/nofile.$test_count
EOF
    test_path_is_missing dir.$test_count/nofile.$test_count
'

test_expect_success 'magic core/violation/raise_safe:1 works' '
    : > file.$test_count &&
    test_must_violate sydbox \
        -m core/violation/raise_safe:1 \
        -m core/sandbox/write:deny \
        -- emily access -e EACCES -w file.$test_count
'

test_done
