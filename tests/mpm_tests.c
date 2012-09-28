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
        printf("WARNING: mpm_compile is failed: %s\n\n", mpm_error_to_string(error_code));
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

    test_single_match("^aa", MPM_ADD_VERBOSE, MPM_COMPILE_VERBOSE, subjects1);
    test_single_match("^aa", MPM_ADD_MULTILINE | MPM_ADD_VERBOSE, MPM_ADD_MULTILINE | MPM_COMPILE_VERBOSE, subjects2);

    re = test_mpm_create();
    if (!re)
        return;

    test_mpm_add_fail(re, "^(?:a|a*)", MPM_ADD_VERBOSE, MPM_EMPTY_PATTERN);
    test_mpm_add_fail(re, "^(?:a|a*)", MPM_ADD_MULTILINE | MPM_ADD_VERBOSE, MPM_EMPTY_PATTERN);
    test_mpm_add_fail(re, "^a|a", MPM_ADD_VERBOSE, MPM_UNSUPPORTED_PATTERN);
    mpm_free(re);
}

static void test4()
{
    mpm_re *re;

    printf("Test4: A large set.\n\n");

    re = test_mpm_create();
    if (!re)
        return;

    test_mpm_add(re, "\\x3Cobject[^\\x3E]+?data\\s*\\x3D\\s*\\x22\\x22", MPM_ADD_VERBOSE);
    test_mpm_add(re, "^[^\\s]{256}", MPM_ADD_VERBOSE);
    test_mpm_compile(re, MPM_COMPILE_VERBOSE);

    mpm_free(re);
}

#define MAX_TESTS 4

static test_case tests[MAX_TESTS] = {
    test1, test2, test3, test4
};

/* ----------------------------------------------------------------------- */
/*                                 Playground.                             */
/* ----------------------------------------------------------------------- */

#define MAX_LINE_LENGTH 4096

static void load_patterns(char* file_name)
{
    FILE *f = fopen(file_name, "rt");
    mpm_re *re;
    char data[MAX_LINE_LENGTH];
    char *ptr;
    int flags, line, count_supported, count_failed;

    if (!f) {
        printf("Cannot open file: %s\n", file_name);
        return;
    }

    re = test_mpm_create();
    if (!re) {
        fclose(f);
        return;
    }

    count_supported = 0;
    count_failed = 0;
    line = 1;
    while (1) {
        if (!fgets(data, MAX_LINE_LENGTH, f))
            break;

        if (memcmp(data, "regex \"/", 8) == 0 || memcmp(data, "regex !\"/", 9) == 0) {
            ptr = data + strlen(data) - 1;
            if (ptr[0] == '\n')
                ptr--;
            if (ptr[0] != '"') {
                printf("Regex must end with quotation mark\n");
                continue;
            }
            ptr--;
            flags = 0;
            while (ptr[0] != '/') {
                if (ptr < data + 8) {
                    printf("Cannot find terminator slash\n");
                    break;
                }
                switch (ptr[0]) {
                case 'A':
                    flags |= MPM_ADD_ANCHORED;
                    break;
                case 'i':
                    flags |= MPM_ADD_CASELESS;
                    break;
                case 'm':
                    flags |= MPM_ADD_MULTILINE;
                    break;
                case 's':
                    flags |= MPM_ADD_DOTALL;
                    break;
                case 'x':
                    flags |= MPM_ADD_EXTENDED;
                    break;
                case 'B':
                case 'C':
                case 'D':
                case 'G':
                case 'H':
                case 'I':
                case 'P':
                case 'R':
                case 'U':
                    break;
                default:
                    printf("Unknown flag: %c\n", ptr[0]);
                    break;
                }
                ptr--;
            }
            if (ptr[0] != '/')
                continue;

            ptr[0] = '\0';
            ptr = data + ((data[6] == '!') ? 9 : 8);
            if (mpm_add(re, ptr, flags) != MPM_NO_ERROR) {
                printf("Cannot add regex: line:%d %s\n", line, ptr);
                count_failed++;
            } else
                count_supported++;
        } else if (memcmp(data, "pattern ", 8) == 0) {
            ptr = data + strlen(data) - 1;
            if (ptr[0] == '\n')
                ptr--;
            ptr[1] = '\0';

            if (mpm_add(re, data + 8, MPM_ADD_FIXED) != MPM_NO_ERROR) {
                printf("WARNING: Cannot add fixed string: line:%d %s\n", line, data + 8);
                count_failed++;
            } else
                count_supported++;
        } else
            printf("WARNING: Unknown type: line:%d %s\n", line, data);
        line++;
    }

    fclose(f);

    printf("Statistics: Supported: %d Unsupported: %d\n", count_supported, count_failed);
    /* test_mpm_compile(re, MPM_COMPILE_VERBOSE_STATS); */
}

static void new_feature(void)
{
    mpm_re *re;

    printf("Trying a new feature.\n\n");

    re = test_mpm_create();
    if (!re)
        return;

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

/*
    test_mpm_add(re, "a\\x00b.c\\x20\\xffd*", MPM_ADD_FIXED | MPM_ADD_VERBOSE);
    test_mpm_add(re, "X(\\x6a\\x0d)?m\\x0g", MPM_ADD_CASELESS | MPM_ADD_FIXED | MPM_ADD_VERBOSE);
    test_mpm_add(re, "ab.cd*", MPM_ADD_VERBOSE);
*/

    test_mpm_compile(re, MPM_COMPILE_VERBOSE | MPM_COMPILE_VERBOSE_STATS);
    test_mpm_exec(re, "mmaa bb");

    mpm_free(re);

    /* load_patterns("../../patterns.txt"); */
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
