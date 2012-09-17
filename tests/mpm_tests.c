/* Copyright (C) 2012 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Zoltan Herczeg <zherczeg@inf.u-szeged.hu>
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "mpm.h"

/* ----------------------------------------------------------------------- */
/*                               Utility functions.                        */
/* ----------------------------------------------------------------------- */

static int test_failed = 0;

static mpm_re * test_mpm_create()
{
    mpm_re *re = mpm_create();
    if (!re) {
        printf("WARNING: mpm_create is failed: %s\n\n", mpm_error_to_string(MPM_NO_MEMORY));
        test_failed = 1;
    }
    return re;
}

static void test_mpm_add(mpm_re *re, char *pattern, int flags)
{
    int error_code = mpm_add(re, pattern, flags);
    if (error_code != MPM_NO_ERROR) {
        printf("WARNING: mpm_add is failed: %s\n\n", mpm_error_to_string(error_code));
        test_failed = 1;
    }
}

static void test_mpm_add_fail(mpm_re *re, char *pattern, int flags, int error)
{
    int error_code = mpm_add(re, pattern, flags);
    if (error_code != error) {
        printf("WARNING: expected error of mpm_add does not occur!\n\n");
        test_failed = 1;
        return;
    }
    printf("Expected error: '%s' occured\n\n", mpm_error_to_string(error));
}

static void test_mpm_compile(mpm_re *re, int flags)
{
    int error_code = mpm_compile(re, flags);
    if (error_code != MPM_NO_ERROR) {
        printf("WARNING: mpm_add is failed: %s\n\n", mpm_error_to_string(error_code));
        test_failed = 1;
    }
}

static void test_mpm_exec(mpm_re *re, char *subject)
{
    printf("Pattern: /%s/ %s\n", subject, mpm_exec(re, subject, strlen(subject)) ? "matches" : "does not match");
}

static void test_single_match(char *pattern, int add_flags, int compile_flags, char **subject)
{
    mpm_re *re = test_mpm_create();
    if (!re)
        return;

    test_mpm_add(re, pattern, add_flags);
    test_mpm_compile(re, compile_flags);
    while (subject[0]) {
        test_mpm_exec(re, subject[0]);
        subject++;
    }
    puts("");
    mpm_free(re);
}

/* ----------------------------------------------------------------------- */
/*                               Automated tests.                          */
/* ----------------------------------------------------------------------- */

typedef void (*test_case)();

static void test1()
{
    mpm_re *re;

    printf("Test1: Testing character classes.\n\n");

    re = test_mpm_create();
    if (!re)
        return;

    test_mpm_add(re, "aB#.\\x00\\x01\\xff\\xfe", MPM_ADD_VERBOSE);
    test_mpm_add(re, ".[^c][^\\x00][^\\x01][^\\xfe][^\\xff]", MPM_ADD_DOTALL | MPM_ADD_VERBOSE);
    test_mpm_add(re, "aB[^c][^D]#[^#]", MPM_ADD_CASELESS | MPM_ADD_VERBOSE);
    test_mpm_add(re, " [a-z] [\\x00-\\x05y-\\xff]  (?i)[c-fMX] ", MPM_ADD_EXTENDED | MPM_ADD_VERBOSE);
    test_mpm_add(re, " [\\x01\\x02def\\xfd\\xfe]  (?i)[cd\\s]  [\\vedcb \\d] ", MPM_ADD_EXTENDED | MPM_ADD_VERBOSE);
    test_mpm_add(re, "\\d\\D\\w\\W\\s\\S\\h\\H\\v\\V", MPM_ADD_CASELESS | MPM_ADD_VERBOSE);

    mpm_free(re);
}

static void test2()
{
    mpm_re *re;

    printf("Test2: Testing iterators.\n\n");

    re = test_mpm_create();
    if (!re)
        return;

    test_mpm_add(re, "#a+?#b*#c??#d{3,6}#e{0,3}?#f{2,}#", MPM_ADD_VERBOSE);
    test_mpm_add(re, "#a+#b*?#c?#d{3,6}?#e{0,3}#f{2,}?#", MPM_ADD_CASELESS | MPM_ADD_VERBOSE);
    test_mpm_add(re, "#[^a]+?#[^b]*#[^c]??#[^d]{3,6}#[^e]{0,3}?#[^f]{2,}#", MPM_ADD_VERBOSE);
    test_mpm_add(re, "#[^a]+#[^b]*?#[^c]?#[^d]{3,6}?#[^e]{0,3}#[^f]{2,}?#", MPM_ADD_CASELESS | MPM_ADD_VERBOSE);
    test_mpm_add(re, "#\\s+?#\\w*#\\d??#\\h{3,6}#\\w{0,3}?#.{2,}#", MPM_ADD_CASELESS | MPM_ADD_VERBOSE);
    test_mpm_add(re, "#\\S+?#\\W*#\\D??#\\H{6,9}#\\W{0,7}?#.{6,}#", MPM_ADD_DOTALL | MPM_ADD_VERBOSE);
    test_mpm_add(re, "#[a-z]+?#[a-z]*#[a-z]??#[a-z]{3,6}#[a-z]{0,3}?#[a-z]{2,}#", MPM_ADD_VERBOSE);
    test_mpm_add(re, "aa|bb(cc(?:dd|ee)|ff)", MPM_ADD_VERBOSE);
    test_mpm_add_fail(re, "(ab|cd(mn|op)+|ef(gh)?)*", MPM_ADD_VERBOSE, MPM_EMPTY_PATTERN);
    test_mpm_add_fail(re, "a?b?", MPM_ADD_VERBOSE, MPM_EMPTY_PATTERN);
    test_mpm_add_fail(re, "a|b?", MPM_ADD_VERBOSE, MPM_EMPTY_PATTERN);
    test_mpm_add_fail(re, "", MPM_ADD_VERBOSE, MPM_EMPTY_PATTERN);

    mpm_free(re);
}

static void test3()
{
    mpm_re *re;
    char * subjects1[] = { "maab", "aabb", "aa", "a", NULL };
    char * subjects2[] = { "maab", "aabb", "aa", "a", "m\naa", "\r\naa", "a\ra", "\raa\n", NULL };

    printf("Test3: Testing multiline and ^ assertion.\n\n");

    test_single_match("^aa", MPM_ADD_VERBOSE, MPM_ALL_END_STATES | MPM_COMPILE_VERBOSE, subjects1);
    test_single_match("^aa", MPM_ADD_MULTILINE | MPM_ADD_VERBOSE, MPM_ADD_MULTILINE | MPM_ALL_END_STATES | MPM_COMPILE_VERBOSE, subjects2);

    re = test_mpm_create();
    if (!re)
        return;

    test_mpm_add_fail(re, "^(?:a|a*)", MPM_ADD_VERBOSE, MPM_EMPTY_PATTERN);
    test_mpm_add_fail(re, "^(?:a|a*)", MPM_ADD_MULTILINE | MPM_ADD_VERBOSE, MPM_EMPTY_PATTERN);
    test_mpm_add_fail(re, "^a|a", MPM_ADD_VERBOSE, MPM_UNSUPPORTED_PATTERN);
    mpm_free(re);
}

#define MAX_TESTS 3

static test_case tests[MAX_TESTS] = {
    test1, test2, test3
};

/* ----------------------------------------------------------------------- */
/*                                 Playground.                             */
/* ----------------------------------------------------------------------- */

static void new_feature(void)
{
    mpm_re *re;

    printf("Trying a new feature.\n\n");

    re = test_mpm_create();
    if (!re)
        return;

/*
    test_mpm_add(re, "", MPM_ADD_VERBOSE);
    test_mpm_add(re, "(ab)?", MPM_ADD_VERBOSE);
*/

/*
    test_mpm_add(re, "([a0-9]?b)+", MPM_ADD_VERBOSE);
    test_mpm_add(re, "([a0-9]|b*b|[dA-D]+?)x", MPM_ADD_VERBOSE);
    test_mpm_add(re, "([a0-9]|(bc?)|[dC-F](ee|f)*)+", MPM_ADD_VERBOSE);

    test_mpm_add(re, "aa.*bb", MPM_ADD_VERBOSE);
    test_mpm_add(re, "\\s+b+\\w+", MPM_ADD_VERBOSE);
    test_mpm_add(re, "mm(a.+)+dd", MPM_ADD_VERBOSE);
    test_mpm_add(re, "(de.*){2}", MPM_ADD_VERBOSE);

    test_mpm_compile(re, MPM_ALL_END_STATES | MPM_COMPILE_VERBOSE);

    test_mpm_exec(re, "mmaa bbdedde");
*/

    test_mpm_add(re, "^aa.*bb", /*MPM_ADD_ANCHORED |*/ MPM_ADD_MULTILINE | MPM_ADD_VERBOSE);
    test_mpm_compile(re, MPM_ALL_END_STATES | MPM_COMPILE_VERBOSE);
    test_mpm_exec(re, "mmaa bb");

    mpm_free(re);
}

int main(int argc, char* argv[])
{
    int test;

    if (argc >= 2 && argv[1][0] == '-') {
        test = atoi(argv[1] + 1);
        if (test >= 1 && test <= MAX_TESTS) {
            tests[test - 1]();
            return test_failed;
        }

        printf("Test case id must be between 1 and %d\n", MAX_TESTS);
        return 1;
    }

    new_feature();
    return test_failed;
}
