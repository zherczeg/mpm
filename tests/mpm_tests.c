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

#include "mpm.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

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
    int error_code = mpm_add(re, (mpm_char8*)pattern, flags);
    if (error_code != MPM_NO_ERROR) {
        printf("WARNING: mpm_add is failed: %s\n\n", mpm_error_to_string(error_code));
        test_failed = 1;
    }
}

static void test_mpm_add_fail(mpm_re *re, char *pattern, int flags, int error)
{
    int error_code = mpm_add(re, (mpm_char8*)pattern, flags);
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

static void test_mpm_exec(mpm_re *re, char *subject, int offset)
{
    unsigned int result[1];
    int error_code = mpm_exec(re, (mpm_char8*)subject, strlen(subject), offset, result);
    if (error_code != MPM_NO_ERROR) {
        printf("WARNING: mpm_compile is failed: %s\n\n", mpm_error_to_string(error_code));
        test_failed = 1;
        return;
    }
    if (result[0] == 0)
        printf("String: '%s' from %d does not match\n", subject, offset);
    else
        printf("String: '%s' from %d matches (0x%x)\n", subject, offset, (int)result[0]);
}

static void test_multiple_match(mpm_re *re, int compile_flags, char **subject)
{
    test_mpm_compile(re, compile_flags);
    while (subject[0]) {
        test_mpm_exec(re, subject[0], 0);
        subject++;
    }
    puts("");
    mpm_free(re);
}

static void test_single_match(char *pattern, int add_flags, int compile_flags, char **subject)
{
    mpm_re *re = test_mpm_create();
    if (!re)
        return;

    test_mpm_add(re, pattern, add_flags);
    test_multiple_match(re, compile_flags, subject);
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
    test_mpm_add(re, "a.+b*?", MPM_ADD_VERBOSE | MPM_ADD_FIXED(6));
    test_mpm_add(re, "x[Bm]*Y?", MPM_ADD_VERBOSE | MPM_ADD_CASELESS | MPM_ADD_FIXED(6));
    test_mpm_add_fail(re, "(ab|cd(mn|op)+|ef(gh)?)*", MPM_ADD_VERBOSE, MPM_EMPTY_PATTERN);
    test_mpm_add_fail(re, "a?b?", MPM_ADD_VERBOSE, MPM_EMPTY_PATTERN);
    test_mpm_add_fail(re, "a|b?", MPM_ADD_VERBOSE, MPM_EMPTY_PATTERN);
    test_mpm_add_fail(re, "", MPM_ADD_VERBOSE, MPM_EMPTY_PATTERN);
    test_mpm_add_fail(re, "(.)\\1", MPM_ADD_VERBOSE, MPM_UNSUPPORTED_PATTERN);
    test_mpm_add_fail(re, "(?", MPM_ADD_VERBOSE, MPM_INVALID_PATTERN);

    mpm_free(re);
}

static void test3()
{
    mpm_re *re;

    printf("Test3: A large set.\n\n");

    re = test_mpm_create();
    if (!re)
        return;

    test_mpm_add(re, "\\x3Cobject[^\\x3E]+?data\\s*\\x3D\\s*\\x22\\x22", MPM_ADD_VERBOSE);
    test_mpm_add(re, "^[^\\s]{256}", MPM_ADD_VERBOSE);
    test_mpm_compile(re, MPM_COMPILE_VERBOSE | MPM_COMPILE_VERBOSE_STATS);

    mpm_free(re);
}

static void test4()
{
    char * subjects1[] = { "aabc", "a.b+c", "a.b+", "a.b+cd", "mXa.b+c", "na.b+", NULL };
    char * subjects2[] = { "AXX", "[aB]x+", "[Ab]X", "::[AB]X+", "::[ab]x+R", NULL };
    char * subjects3[] = { "m", "abbc", "MaBbcCc", "DeF", "MaBDfA", "de", NULL };
    char * subjects4[] = { "mxnmy", "mxxmnmyn", ":%mxyxmnmyxxn%:", "mnmn", "<<<myynmxxmn>>", NULL };
    char * subjects5[] = { "\x80\x7f\x7f", "\x80\x80\x7f", "\x80\x7f", NULL };

    printf("Test4: Test single matching set.\n\n");

    test_single_match("a.b+c", MPM_ADD_VERBOSE | MPM_ADD_FIXED(5), MPM_COMPILE_VERBOSE | MPM_COMPILE_VERBOSE_STATS, subjects1);
    test_single_match("[Ab]X+", MPM_ADD_VERBOSE | MPM_ADD_CASELESS | MPM_ADD_FIXED(6), MPM_COMPILE_VERBOSE | MPM_COMPILE_VERBOSE_STATS, subjects2);
    test_single_match("a?b*(cc+|de?f)", MPM_ADD_VERBOSE | MPM_ADD_CASELESS, MPM_COMPILE_VERBOSE | MPM_COMPILE_VERBOSE_STATS, subjects3);
    test_single_match("(m[xy]+m?n){2}", MPM_ADD_VERBOSE, MPM_COMPILE_VERBOSE | MPM_COMPILE_VERBOSE_STATS, subjects4);
    test_single_match("\\x7f{2}", MPM_ADD_VERBOSE, MPM_COMPILE_VERBOSE | MPM_COMPILE_VERBOSE_STATS, subjects5);
    test_single_match("\\x80{2}", MPM_ADD_VERBOSE, MPM_COMPILE_VERBOSE | MPM_COMPILE_VERBOSE_STATS, subjects5);
    test_single_match("[a-\\x90]{3}", MPM_ADD_VERBOSE, MPM_COMPILE_VERBOSE | MPM_COMPILE_VERBOSE_STATS, subjects5);
}

static void test5()
{
    printf("Test5: Multiple matching set.\n\n");
}

static void test6()
{
    mpm_re *re;
    int i;
    char * subjects1[] = { "maab", "aabb", "aa", "a", NULL };
    char * subjects2[] = { "maab", "aabb", "aa", "a", "m\naa", "\r\naa", "a\ra", "\raa\n", NULL };
    char * subjects3[] = { "m\xab", "\n\xab", "\xab\n", NULL };

    printf("Test6: Testing multiline and ^ assertion.\n\n");

    test_single_match("^aa", MPM_ADD_VERBOSE, MPM_COMPILE_VERBOSE | MPM_COMPILE_VERBOSE_STATS, subjects1);
    test_single_match("^aa", MPM_ADD_MULTILINE | MPM_ADD_VERBOSE, MPM_COMPILE_VERBOSE | MPM_COMPILE_VERBOSE_STATS, subjects2);
    test_single_match("^\\xab", MPM_ADD_MULTILINE | MPM_ADD_VERBOSE, MPM_COMPILE_VERBOSE | MPM_COMPILE_VERBOSE_STATS, subjects3);
    test_single_match("^[^\\xab]", MPM_ADD_MULTILINE | MPM_ADD_VERBOSE, MPM_COMPILE_VERBOSE | MPM_COMPILE_VERBOSE_STATS, subjects3);

    re = test_mpm_create();
    if (!re)
        return;

    test_mpm_add_fail(re, "^(?:a|a*)", MPM_ADD_VERBOSE, MPM_EMPTY_PATTERN);
    test_mpm_add_fail(re, "^(?:a|a*)", MPM_ADD_MULTILINE | MPM_ADD_VERBOSE, MPM_EMPTY_PATTERN);
    test_mpm_add_fail(re, "^a|a", MPM_ADD_VERBOSE, MPM_UNSUPPORTED_PATTERN);

    for (i = 0; i < 32; i++)
        test_mpm_add(re, "A", 0);
    test_mpm_add_fail(re, "B", 0, MPM_PATTERN_LIMIT);
    mpm_free(re);
}

static void test7()
{
    mpm_re *re;

    printf("Test7: Testing offsets.\n\n");

    re = test_mpm_create();
    if (!re)
        return;

    printf("\nTest1:\n");
    test_mpm_add(re, "^a", MPM_ADD_MULTILINE);
    test_mpm_add(re, "^a", 0);
    test_mpm_add(re, "\\na", 0);
    test_mpm_compile(re, 0);
    test_mpm_exec(re, "a\na", 0);
    test_mpm_exec(re, "a\na", 2);
    test_mpm_exec(re, "a\na\na", 2);
    mpm_free(re);

    re = test_mpm_create();
    if (!re)
        return;

    printf("\nTest2:\n");
    test_mpm_add(re, "^a", 0);
    test_mpm_add(re, "\\na", 0);
    test_mpm_compile(re, 0);
    test_mpm_exec(re, "a\na", 0);
    test_mpm_exec(re, "a\na\n", 2);
    test_mpm_exec(re, "a\na\na", 2);
    mpm_free(re);

    re = test_mpm_create();
    if (!re)
        return;

    printf("\nTest3:\n");
    test_mpm_add(re, "^a", MPM_ADD_MULTILINE);
    test_mpm_add(re, "\\na", 0);
    test_mpm_compile(re, 0);
    test_mpm_exec(re, "a\na", 0);
    test_mpm_exec(re, "a\na\nb", 2);
    test_mpm_exec(re, "a\na\na", 2);
    mpm_free(re);
}

#define MAX_TESTS 7

static test_case tests[MAX_TESTS] = {
    test1, test2, test3, test4, test5,
    test6, test7
};

/* ----------------------------------------------------------------------- */
/*                                 Playground.                             */
/* ----------------------------------------------------------------------- */

#define MAX_LINE_LENGTH 4096
#define MAX_RE_GROUPS 16

static mpm_re *loaded_re[MAX_RE_GROUPS];
static char *input;
static unsigned long input_length;

static int is_hex_number(char ch)
{
    return ((ch >= '0' && ch <= '9') || ((ch | 0x20) >= 'a' && (ch | 0x20) <= 'f'));
}

static unsigned int hex_number_value(char ch)
{
    return ch <= '9' ? ch - '0' : ((ch | 0x20) + 10 - 'a');
}

static int process_regex(char *data)
{
    int flags = 0;
    char *current;

    current = data + strlen(data) - 1;
    if (current[0] == '\n')
        current--;
    if (current[0] != '"') {
        printf("Regex must end with quotation mark\n");
        return -1;
    }
    current--;
    while (current[0] != '/') {
        if (current < data + 8) {
            printf("Cannot find terminator slash\n");
            return -1;
        }
        switch (current[0]) {
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
            printf("Unknown flag: %c\n", current[0]);
            return -1;
        }
        current--;
    }

    current[0] = '\0';
    return flags;
}

static char* process_fixed_string(char *source)
{
    unsigned int value;
    char *destination;

    source += 8;
    destination = source;
    while (source[0]) {
        value = (unsigned char)source[0];
        if (value == '\\' && source[1] == 'x' && is_hex_number(source[2]) && is_hex_number(source[3])) {
            value = hex_number_value(source[2]) << 4 | hex_number_value(source[3]);
            source += 3;
        }
        source++;
        *destination++ = value;
    }

    if (destination[-1] == '\n') {
        destination--;
        destination[0] = '\0';
    }
    return destination;
}

static void load_patterns(char* file_name,
    int load_regexes, int load_patterns, int max_loaded, int groups)
{
    FILE *f = fopen(file_name, "rt");
    char data[MAX_LINE_LENGTH];
    char *ptr;
    int group_id, flags, line, count_supported, count_failed;

    if (!f) {
        printf("Cannot open file: %s\n", file_name);
        return;
    }

    if (!max_loaded)
        max_loaded = 0x7fffffff;

    if (groups <= 0)
        groups = 1;
    if (groups >= MAX_RE_GROUPS)
        groups = MAX_RE_GROUPS;

    for (group_id = 0; group_id < groups; group_id++) {
        loaded_re[group_id] = test_mpm_create();
        if (!loaded_re[group_id]) {
            fclose(f);
            return;
        }
    }

    count_supported = 0;
    count_failed = 0;
    line = 1;
    group_id = 0;

    while (count_supported < max_loaded) {
        if (!fgets(data, MAX_LINE_LENGTH, f))
            break;

        if (memcmp(data, "regex \"/", 8) == 0 || memcmp(data, "regex !\"/", 9) == 0) {
            if (!load_regexes)
                continue;

            flags = process_regex(data);
            /* An error happened. */
            if (flags == -1)
                continue;

            ptr = data + ((data[6] == '!') ? 9 : 8);
            if (mpm_add(loaded_re[group_id], (mpm_char8*)ptr, flags) != MPM_NO_ERROR) {
                printf("Cannot add regex: line:%d %s\n", line, ptr);
                count_failed++;
            } else {
                count_supported++;
                group_id = (group_id + 1) % groups;
            }
        } else if (memcmp(data, "pattern ", 8) == 0) {
            if (!load_patterns)
                continue;

            ptr = process_fixed_string(data);
            if (mpm_add(loaded_re[group_id], (mpm_char8*)(data + 8), MPM_ADD_FIXED(ptr - (data + 8))) != MPM_NO_ERROR) {
                printf("WARNING: Cannot add fixed string: line:%d %s\n", line, data + 8);
                count_failed++;
            } else {
                count_supported++;
                group_id = (group_id + 1) % groups;
            }
        } else
            printf("WARNING: Unknown type: line:%d %s\n", line, data);
        line++;
    }

    fclose(f);

    printf("Statistics: Supported: %d Unsupported: %d\n", count_supported, count_failed);
    for (group_id = 0; group_id < groups; group_id++)
         test_mpm_compile(loaded_re[group_id], MPM_COMPILE_VERBOSE_STATS);
}

static void load_input(char *file_name)
{
    FILE *f = fopen(file_name, "rt");
    unsigned long length;

    if (!f)
        return;

    fseek(f, 0, SEEK_END);
    length = ftell(f);
    fseek(f, 0, SEEK_SET);

    input = (char*)malloc(length);
    if (!input) {
        fclose(f);
        return;
    }

    fread(input, 1, length, f);
    fclose(f);
    printf("File: %s (%d) loaded\n", file_name, (int)length);
    input_length = length;
}

static void search_patterns(char* file_name, char *pattern, int flags, int lower_bound)
{
    FILE *f = fopen(file_name, "rt");
    char data[MAX_LINE_LENGTH];
    int line, value;
    mpm_re *re_base;
    mpm_re *re_current;
    char *ptr;

    if (!f) {
        printf("Cannot open file: %s\n", file_name);
        return;
    }

    re_base = mpm_create();
    if (!re_base) {
        printf("WARNING: mpm_create is failed: %s\n", mpm_error_to_string(MPM_NO_MEMORY));
        return;
    }

    value = mpm_add(re_base, (mpm_char8*)pattern, flags);
    if (value != MPM_NO_ERROR) {
        printf("WARNING: mpm_add is failed: %s\n", mpm_error_to_string(value));
        return;
    }

    printf("Searching similar patterns for: '%s'\n", pattern);

    line = 1;
    while (1) {
        if (!fgets(data, MAX_LINE_LENGTH, f))
            break;

        re_current = mpm_create();
        if (!re_current) {
            printf("WARNING: mpm_create is failed: %s\n", mpm_error_to_string(MPM_NO_MEMORY));
            return;
        }

        if (memcmp(data, "regex \"/", 8) == 0 || memcmp(data, "regex !\"/", 9) == 0) {
            flags = process_regex(data);
            /* An error happened. */
            if (flags == -1)
                continue;

            ptr = data + ((data[6] == '!') ? 9 : 8);
            if (mpm_add(re_current, (mpm_char8*)ptr, flags) != MPM_NO_ERROR) {
                /* printf("Cannot add regex: line:%d %s\n", line, ptr); */
                ptr = NULL;
            }
        } else if (memcmp(data, "pattern ", 8) == 0) {
            ptr = process_fixed_string(data);
            if (mpm_add(re_current, (mpm_char8*)(data + 8), MPM_ADD_FIXED(ptr - (data + 8))) != MPM_NO_ERROR) {
                /* printf("WARNING: Cannot add fixed string: line:%d %s\n", line, data + 8); */
                ptr = NULL;
            } else
                ptr = data + 8;
        } else {
            ptr = NULL;
            printf("WARNING: Unknown type: line:%d %s\n", line, data);
        }

        if (ptr) {
            value = mpm_distance(re_base, 0, re_current, 0);
            if (value <= 0) {
                if (value >= lower_bound)
                    printf("  distance of '%s' is %d\n", ptr, value);
            } else {
                printf("<%s> %d\n", ptr, value);
                printf("WARNING: mpm_distance is failed: %s\n", mpm_error_to_string(value));
            }
        }

        mpm_free(re_current);
        line++;
    }

    fclose(f);
    mpm_free(re_base);
}


static void new_feature(void)
{
#if 0

    mpm_re *re;

    re = test_mpm_create();
    if (!re)
        return;

    test_mpm_add(re, "aa.b*", MPM_ADD_VERBOSE);
    test_mpm_add(re, "ma?", MPM_ADD_VERBOSE);
    test_mpm_add(re, "aa", MPM_ADD_VERBOSE | MPM_ADD_FIXED(2));
    printf("Distance: %d\n", mpm_distance(re, 0, re, 1));
    test_mpm_compile(re, MPM_COMPILE_VERBOSE | MPM_COMPILE_VERBOSE_STATS);
    test_mpm_exec(re, "mmaa bb", 0);
    test_mpm_exec(re, "aa", 0);
    test_mpm_exec(re, "aax", 0);

    mpm_free(re);

#elif 0

    int i;
    clock_t time;
    unsigned int results[8];

    load_patterns("../../patterns3.txt",
        /* load_regexes */ 1,
        /* load_patterns */ 1,
        /* max_loaded */ 128,
        /* groups */ 4);

    load_input("../../input.txt");

    time = clock();
    for (i = 0; i < 32; ++i)
        mpm_exec(loaded_re[0], (mpm_char8*)input, input_length, 0, results);
    time = clock() - time;
    printf("Sequential run: %d ms (average)\n", (int)(time * 1000 / (CLOCKS_PER_SEC * 32)));

    if (loaded_re[3]) {
        time = clock();
        for (i = 0; i < 32; ++i)
            mpm_exec4(loaded_re, (mpm_char8*)input, input_length, 0, results);
        time = clock() - time;
        printf("Parallel run (4): %d ms (average)\n", (int)(time * 1000 / (CLOCKS_PER_SEC * 32)));
    }

#else

    search_patterns("../../patterns.txt", "sitepath=\\s*(ftps?|https?|php)\\:\\/", MPM_ADD_CASELESS, -10);

#endif
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

    printf("Trying a new feature.\n\n");
    new_feature();

    return test_failed;
}
