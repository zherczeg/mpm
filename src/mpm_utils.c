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

#include "mpm_internal.h"

/* ----------------------------------------------------------------------- */
/*                               Core functions.                           */
/* ----------------------------------------------------------------------- */

mpm_re * mpm_create(void)
{
    mpm_re *re = (mpm_re *)malloc(sizeof(mpm_re));
    if (!re)
        return NULL;

    re->flags = RE_MODE_COMPILE;
    re->compile.patterns = NULL;
    re->compile.next_id = 0;
    re->compile.next_term_index = 0;

    return re;
}

void mpm_private_free_patterns(mpm_re_pattern *pattern)
{
    mpm_re_pattern *next;
    while (pattern) {
        next = pattern->next;
        free(pattern);
        pattern = next;
    }
}

void mpm_free(mpm_re *re)
{
    if (re->flags & RE_MODE_COMPILE) {
        if (re->compile.patterns)
            mpm_private_free_patterns(re->compile.patterns);
    } else {
        if (re->run.compiled_pattern)
            free(re->run.compiled_pattern);
    }
    free(re);
}

void mpm_rule_list_free(mpm_rule_list *rule_list)
{
    pattern_list_item *pattern_list = rule_list->pattern_list;
    pattern_list_item *pattern_list_end = pattern_list + rule_list->pattern_list_length;
    while (pattern_list < pattern_list_end) {
        mpm_free(pattern_list->re);
        pattern_list++;
    }

    free(rule_list->rule_indices);
    free(rule_list);
}

char *mpm_error_to_string(int error_code)
{
    switch (error_code) {
    case MPM_NO_ERROR:
        return "No error";
    case MPM_NO_MEMORY:
        return "Out of memory occured";
    case MPM_INTERNAL_ERROR:
        return "Internal error (should never happen)";
    case MPM_INVALID_PATTERN:
        return "Pattern cannot be compiled by PCRE";
    case MPM_UNSUPPORTED_PATTERN:
        return "Pattern is not supported by MPM library";
    case MPM_EMPTY_PATTERN:
        return "Pattern matches an empty string (matches to any input)";
    case MPM_INVALID_ARGS:
        return "Invalid or unsupported arguments";
    case MPM_PATTERN_LIMIT:
        return "Cannot add more regular expressions (max " TOSTRING(PATTERN_LIMIT) ")";
    case MPM_TOO_LOW_RATING:
        return "Pattern is not suitable for a DFA based engine";
    case MPM_RE_ALREADY_COMPILED:
        return "Pattern has been already compiled by mpm_compile";
    case MPM_RE_IS_NOT_COMPILED:
        return "Pattern must be compiled first by mpm_compile";
    case MPM_STATE_MACHINE_LIMIT:
        return "Number of allowed states is reached (max " TOSTRING(STATE_LIMIT) " states)";
    case MPM_NO_SUCH_PATTERN:
        return "No such pattern (invalid index argument)";
    default:
        return "Unknown error code";
    }
}

mpm_size mpm_private_get_pattern_size(mpm_re_pattern *pattern)
{
     /* Get the total size in bytes of the DFA. */
     mpm_uint32 *word_code = pattern->word_code;
     word_code += pattern->word_code[pattern->term_range_size - 1];
     word_code += CHAR_SET_SIZE + 1;

     while (*word_code != DFA_NO_DATA)
         word_code++;

     word_code++;
     return sizeof(mpm_re_pattern) + ((word_code - pattern->word_code - 1) << 2);
}

int mpm_combine(mpm_re **destination_re, mpm_re *source_re, mpm_uint32 flags)
{
    mpm_re_pattern *pattern;
    mpm_re_pattern *new_pattern;
    mpm_re_pattern *prev_pattern;
    mpm_re_pattern *first_pattern;
    mpm_size size;
    mpm_uint32 i, id, term_index;
    mpm_uint32 *word_code;

    /* Sanity check. */
    if (!source_re || !destination_re || destination_re[0] == source_re)
        return MPM_INVALID_ARGS;

    if ((destination_re[0] && !(destination_re[0]->flags & RE_MODE_COMPILE)) || !(source_re->flags & RE_MODE_COMPILE))
        return MPM_RE_ALREADY_COMPILED;

    pattern = source_re->compile.patterns;
    i = 0;
    while (pattern) {
        pattern = pattern->next;
        i++;
    }
    if (i != source_re->compile.next_id)
        return MPM_INTERNAL_ERROR;

    if (destination_re[0]) {
        pattern = destination_re[0]->compile.patterns;
        i = 0;
        while (pattern) {
            pattern = pattern->next;
            i++;
        }
        if (i != destination_re[0]->compile.next_id)
            return MPM_INTERNAL_ERROR;

        if (destination_re[0]->compile.next_id + source_re->compile.next_id > PATTERN_LIMIT)
            return MPM_PATTERN_LIMIT;
    }

    /* Copy pattern if necessary. */
    if (flags & MPM_COMBINE_COPY) {
        pattern = source_re->compile.patterns;
        first_pattern = NULL;
        prev_pattern = NULL;
        while (pattern) {
            size = mpm_private_get_pattern_size(pattern);
            new_pattern = (mpm_re_pattern *)malloc(size);
            if (!new_pattern) {
                mpm_private_free_patterns(first_pattern);
                return MPM_NO_MEMORY;
            }
            memcpy(new_pattern, pattern, size);
            new_pattern->next = NULL;
            if (prev_pattern)
                prev_pattern->next = new_pattern;
            else
                first_pattern = new_pattern;
            prev_pattern = new_pattern;
            pattern = pattern->next;
        }
    } else
        first_pattern = source_re->compile.patterns;

    if (!destination_re[0]) {
        destination_re[0] = mpm_create();
        if (!destination_re[0]) {
            if (flags & MPM_COMBINE_COPY)
                mpm_private_free_patterns(first_pattern);
            return MPM_NO_MEMORY;
        }
    }

    if (!destination_re[0]->compile.patterns)
        destination_re[0]->compile.patterns = first_pattern;
    else {
        pattern = destination_re[0]->compile.patterns;
        while (pattern->next)
            pattern = pattern->next;
        pattern->next = first_pattern;

        id = destination_re[0]->compile.next_id;
        term_index = destination_re[0]->compile.next_term_index;
        pattern = pattern->next;
        while (pattern) {
            pattern->term_range_start += term_index;
            word_code = pattern->word_code + pattern->term_range_size;
            if (*word_code != DFA_NO_DATA)
                *word_code += id;
            while (*(++word_code) != DFA_NO_DATA)
                *word_code += term_index;

            for (i = 0; i < pattern->term_range_size; i++) {
                word_code = pattern->word_code + pattern->word_code[i] + CHAR_SET_SIZE;
                if (*word_code != DFA_NO_DATA)
                    *word_code += id;
                while (*(++word_code) != DFA_NO_DATA)
                     *word_code += term_index;
            }
            pattern = pattern->next;
        }
    }

    destination_re[0]->compile.next_id += source_re->compile.next_id;
    destination_re[0]->compile.next_term_index += source_re->compile.next_term_index;

    if (!(flags & MPM_COMBINE_COPY))
        free(source_re);
    return MPM_NO_ERROR;
}

/* ----------------------------------------------------------------------- */
/*                             Verbose functions.                          */
/* ----------------------------------------------------------------------- */

#if defined MPM_VERBOSE && MPM_VERBOSE
static void print_character(int character)
{
    if (character >= 0x20 && character <= 0x7e && character != '-')
        printf("%c", character);
    else if (character <= 0xf)
        printf("\\x0%x", character);
    else
        printf("\\x%x", character);
}

/* Exported function. */
void mpm_private_print_char_range(mpm_uint8 *bitset)
{
    int bit = 0x01;
    int character = 0;
    int last_set_character = -1;

    do {
        if (bitset[0] & bit) {
            if (last_set_character < 0) {
                print_character(character);
                last_set_character = character;
            }
        } else if (last_set_character >= 0) {
            if (character == last_set_character + 2)
                print_character(character - 1);
            else if (character > last_set_character + 2) {
                printf("-");
                print_character(character - 1);
            }
            last_set_character = -1;
        }

        bit <<= 1;
        if (bit == 0x100) {
            bit = 0x01;
            bitset++;
        }
        character++;
    } while (character < 256);

    if (last_set_character == 254)
        printf("\\xff");
    else if (last_set_character <= 253 && last_set_character >= 0)
        printf("-\\xff");
}
#endif
