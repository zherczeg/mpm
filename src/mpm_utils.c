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

    re->next_id = 1;
    re->next_term_index = 0;
    re->flags = 0;
    re->patterns = NULL;
    re->compiled_pattern = NULL;

    return re;
}

void mpm_free_patterns(mpm_re_pattern *pattern)
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
    if (re->patterns)
        mpm_free_patterns(re->patterns);
    if (re->compiled_pattern)
        free(re->compiled_pattern);
    free(re);
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
    case MPM_EMPTY_PATTERN:
        return "Pattern matches an empty string";
    case MPM_UNSUPPORTED_PATTERN:
        return "Pattern is not supported by MPM";
    case MPM_RE_ALREADY_COMPILED:
        return "Patter has been already compiled by mpm_compile";
    default:
        return "Unknown error";
    }
}

/* ----------------------------------------------------------------------- */
/*                             Verbose functions.                          */
/* ----------------------------------------------------------------------- */

#if defined MPM_VERBOSE && MPM_VERBOSE
static void print_character(int character)
{
    if (character >= 0x20 && character <= 0x7f && character != '-')
        printf("%c", character);
    else if (character <= 0xf)
        printf("\\x0%x", character);
    else
        printf("\\x%x", character);
}

/* Exported function. */
void mpm_print_char_range(uint8_t *bitset)
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
