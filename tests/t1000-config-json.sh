#!/bin/sh
# Copyright 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='test JSON parser'
. ./test-lib.sh

test_external_has_tap=1

# All this hackery below with test counts is to prove `prove'
# that this test is TAP compatible :S
pass_tests_count=3
fail_tests_count=33

echo "1..$(expr ${pass_tests_count} + ${fail_tests_count})"
for i in $(seq 1 ${pass_tests_count}); do
    json_parser_round=${i}
    export json_parser_round

    test_external "JSON parser pass/${i}" \
                   jsontest \
                  "${TEST_DIRECTORY}"/json/pass${i}.json
done

for i in $(seq 1 ${fail_tests_count}); do
    json_parser_round=$(expr ${pass_tests_count} + ${i})
    export json_parser_round

    test_external "JSON parser fail/${i}" \
                  jsontest \
                  "${TEST_DIRECTORY}"/json/fail${i}.json
done

test_done
