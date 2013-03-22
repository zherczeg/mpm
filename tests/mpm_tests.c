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

/* load_pattern */
static mpm_re *loaded_re[MAX_RE_GROUPS];

/* load_pattern_list */
static mpm_cluster_item *loaded_items;
static int loaded_items_size;

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

typedef struct compiled_pattern {
    struct compiled_pattern *next;
    mpm_re *re;
    char *pattern;
} compiled_pattern;

static void load_pattern_list(char* file_name)
{
    FILE *f = fopen(file_name, "rt");
    char data[MAX_LINE_LENGTH];
    int line, count, skipped_count, unsupported_count, flags, len;
    compiled_pattern *first_pattern, *last_pattern;
    compiled_pattern *current_pattern;
    mpm_re *current_re;
    mpm_cluster_item *loaded_items_ptr;
    char *ptr;

    if (!f) {
        printf("Cannot open file: %s\n", file_name);
        return;
    }

    line = 1;
    count = 0;
    skipped_count = 0;
    unsupported_count = 0;
    first_pattern = NULL;
    last_pattern = NULL;
    while (1) {
        if (!fgets(data, MAX_LINE_LENGTH, f))
            break;

        current_re = mpm_create();
        if (!current_re) {
            printf("WARNING: mpm_create is failed: %s\n", mpm_error_to_string(MPM_NO_MEMORY));
            return;
        }

        if (memcmp(data, "regex \"/", 8) == 0 || memcmp(data, "regex !\"/", 9) == 0) {
            flags = process_regex(data);
            /* An error happened. */
            if (flags == -1)
                continue;

            ptr = data + ((data[6] == '!') ? 9 : 8);
            flags = mpm_add(current_re, (mpm_char8*)ptr, flags | MPM_ADD_TEST_RATING);
            if (flags != MPM_NO_ERROR) {
                printf("Warning: mpm_add returned with '%s' in line:%d '%s'\n", mpm_error_to_string(flags), line, ptr);
                ptr = NULL;
            }

            len = strlen(data);
            data[len] = '/';
            len += strlen(data + len);
            if (data[len - 1] == '\n')
                data[len - 1] = '\0';
        } else if (memcmp(data, "pattern ", 8) == 0) {
            ptr = process_fixed_string(data);
            flags = mpm_add(current_re, (mpm_char8*)(data + 8), MPM_ADD_FIXED(ptr - (data + 8)) | MPM_ADD_TEST_RATING);
            if (flags != MPM_NO_ERROR) {
                printf("Warning: mpm_add returned with '%s' in line:%d '%s'\n", mpm_error_to_string(flags), line, data + 8);
                ptr = NULL;
            } else
                ptr = data + 8;
        } else {
            flags = MPM_NO_ERROR;
            ptr = NULL;
            printf("Warning: Unknown type: line:%d %s\n", line, data);
        }

        if (flags == MPM_TOO_LOW_RATING)
            skipped_count++;
        else if (flags != MPM_NO_ERROR)
            unsupported_count++;

        line++;
        if (!ptr) {
            mpm_free(current_re);
            continue;
        }

        ptr = data;
        current_pattern = (compiled_pattern *)malloc(sizeof(compiled_pattern));
        if (!current_pattern) {
            printf("WARNING: out of memory\n");
            return;
        }

        len = strlen(ptr);
        current_pattern->pattern = (char *)malloc(len + 1);
        if (!current_pattern->pattern) {
            printf("WARNING: out of memory\n");
            return;
        }
        memcpy(current_pattern->pattern, ptr, len + 1);

        current_pattern->next = NULL;
        current_pattern->re = current_re;
        if (!first_pattern)
            first_pattern = current_pattern;
        else
            last_pattern->next = current_pattern;
        last_pattern = current_pattern;

        count++;
    }

    fclose(f);

    if (!count)
        return;

    loaded_items = (mpm_cluster_item *)malloc(count * sizeof(mpm_cluster_item));
    if (!loaded_items) {
        printf("WARNING: out of memory\n");
        return;
    }

    loaded_items_size = count;

    /* Copy the data. */
    loaded_items_ptr = loaded_items;
    while (first_pattern) {
        loaded_items_ptr->re = first_pattern->re;
        loaded_items_ptr->data = first_pattern->pattern;
        loaded_items_ptr++;

        last_pattern = first_pattern->next;
        free(first_pattern);
        first_pattern = last_pattern;
    }

    line = count + skipped_count + unsupported_count;
    printf("%d patterns are processed\n  %d (%d%%) successfully loaded\n"
           "  %d (%d%%) ignored because of low rating\n  %d (%d%%) ignored because they are unsupported\n\n",
           line, count, count * 100 / line, skipped_count, skipped_count * 100 / line,
           unsupported_count, unsupported_count * 100 / line);
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

#elif 0

    mpm_re *re;
    int i;

    load_pattern_list("../../patterns3.txt");
    if (!loaded_items)
        return;

    mpm_clustering(loaded_items, loaded_items_size, MPM_CLUSTERING_VERBOSE);

    printf("Group 0:\n  %s\n", (char *)loaded_items[i].data);
    re = loaded_items[0].re;
    for (i = 1; i < loaded_items_size; i++) {
        if (loaded_items[i].group_id != loaded_items[i - 1].group_id) {
            if (mpm_compile(re, MPM_COMPILE_VERBOSE_STATS) != MPM_NO_ERROR)
                printf("WARNING: mpm_compile failed\n");
            printf("\nGroup: %d\n", loaded_items[i].group_id);
            re = loaded_items[i].re;
        } else {
            if (mpm_combine(re, loaded_items[i].re) != MPM_NO_ERROR)
                printf("WARNING: mpm_combine failed\n");
        }

        printf("  %s\n", (char *)loaded_items[i].data);
    }

    mpm_compile(re, MPM_COMPILE_VERBOSE_STATS);

#elif 0

    mpm_rule_list *rule_list;

    mpm_rule_pattern rules[] = {
        /* Rule 0 */
        { (mpm_char8 *)"abc{2}", MPM_RULE_NEW | MPM_ADD_CASELESS },
        { (mpm_char8 *)"a*b", 0 },

        /* Rule 1 */
        { (mpm_char8 *)"abcc", MPM_RULE_NEW | MPM_ADD_CASELESS },
        { (mpm_char8 *)"a*b", 0 },
        { (mpm_char8 *)"(a)\\1", 0 },

        /* Rule 2 */
        { (mpm_char8 *)"(a)\\1", MPM_RULE_NEW },
        { (mpm_char8 *)"V.e.r.y long pattern #########.#########.A", 0 },
        { (mpm_char8 *)"(?=a)aa", 0 },

        /* Rule 3 */
        { (mpm_char8 *)"evil.+software", MPM_RULE_NEW | MPM_ADD_DOTALL },
        { (mpm_char8 *)"Rule#1", MPM_ADD_FIXED(6) },
        { (mpm_char8 *)"Rule#2", MPM_ADD_FIXED(6) },
        { (mpm_char8 *)"Rule#3", MPM_ADD_FIXED(6) },
        { (mpm_char8 *)"Rule#4", MPM_ADD_FIXED(6) },

        /* Rule 4 */
        { (mpm_char8 *)"evil..*software", MPM_RULE_NEW | MPM_ADD_DOTALL },
        { (mpm_char8 *)"V.e.r.y long pattern #########.#########.B", 0 },
        { (mpm_char8 *)"Rule#2", MPM_ADD_FIXED(6) },
        { (mpm_char8 *)"Rule#3", MPM_ADD_FIXED(6) },
        { (mpm_char8 *)"Rule#4", MPM_ADD_FIXED(6) },
        { (mpm_char8 *)"Rule#5", MPM_ADD_FIXED(6) },
        { (mpm_char8 *)"Rule#6", MPM_ADD_FIXED(6) },
        { (mpm_char8 *)"(?=a)aa", 0 },

        /* Rule 5 */
        { (mpm_char8 *)"12345678901234567890123456789012345678901234567890", MPM_RULE_NEW | MPM_ADD_DOTALL },
        { (mpm_char8 *)"V.e.r.y long pattern #########.#########.B", 0 },
        { (mpm_char8 *)"Rule#5", MPM_ADD_FIXED(6) },
        { (mpm_char8 *)"Rule#6", MPM_ADD_FIXED(6) },
        { (mpm_char8 *)"Rule#7", MPM_ADD_FIXED(6) },
        { (mpm_char8 *)"Rule#8", MPM_ADD_FIXED(6) },
    };

    mpm_compile_rules(rules, sizeof(rules) / sizeof(mpm_rule_pattern), &rule_list, MPM_COMPILE_RULES_VERBOSE);
    mpm_rule_list_free(rule_list);

#elif 1

    mpm_rule_list *rule_list;
    mpm_uint32 result[2] = { 0, 0 };

    mpm_rule_pattern rules[] = {
        { (mpm_char8 *)"RULE_01", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_02", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_03", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_04", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_05", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_06", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_07", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_08", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_09", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_10", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_11", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_12", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_13", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_14", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_15", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_16", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_17", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_18", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_19", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_20", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_21", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_22", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_23", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_24", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_25", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_26", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_27", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_28", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_29", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_30", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_31", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_32", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_33", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_34", MPM_RULE_NEW },
        { (mpm_char8 *)"RULE_35", MPM_RULE_NEW },
    };
    char *subject = "RULE_01 RULE_02 RULE_32 RULE_33 RULE_ RULE_35";

    mpm_compile_rules(rules, sizeof(rules) / sizeof(mpm_rule_pattern), &rule_list, MPM_COMPILE_RULES_VERBOSE);
    mpm_exec_list(rule_list, (mpm_char8 *)subject, strlen(subject), 0, result);
    mpm_rule_list_free(rule_list);

    printf("Result: 0x%x 0x%x\n", result[0], result[1]);

#else

    /* Ignore this case. */

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
