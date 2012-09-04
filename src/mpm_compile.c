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
#include "mpm_internal.h"
#include "mpm_pcre_internal.h"

mpm_re * mpm_create(void)
{
    mpm_re *re = (mpm_re *)malloc(sizeof(mpm_re));
    if (!re)
        return NULL;

    re->next_id = 1;
    re->next_term = 0;
    re->patterns = NULL;

    return re;
}

static void free_patterns(mpm_re_pattern *pattern)
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
        free_patterns(re->patterns);
    free(re);
}

/* Recursive function to get the size of the DFA representation. */
static int get_dfa_size(pcre_uchar *code, pcre_uchar *end)
{
   int size = 0;
   while (code < end) {
       switch (code[0]) {
       case OP_ANY:
       case OP_ALLANY:
           size += 9;
           code++;
           break;

       case OP_CHAR:
       case OP_CHARI:
       case OP_NOT:
       case OP_NOTI:
           size += 9;
           code += 2;
           break;

       case OP_CLASS:
       case OP_NCLASS:
           size += 9;
           code += 1 + 32 / sizeof(pcre_uchar);
           break;

       default:
           return -1;
       }
   }
   return size;
}

/* Recursive function to generate the DFA representation. */
static uint32_t * generate_dfa(mpm_re *re, uint32_t *word_code, pcre_uchar *code, pcre_uchar *end)
{
   while (code < end) {
       switch (code[0]) {
       case OP_ANY:
       case OP_ALLANY:
           word_code[0] = OPCODE_SET | (re->next_term++ << OPCODE_ARG_SHIFT);
           SET1(word_code + 1);
           if (code[0] == OP_ANY) {
               RESETBIT(word_code + 1, '\r');
               RESETBIT(word_code + 1, '\n');
           }
           word_code += 9;
           code++;
           break;

       case OP_CHAR:
       case OP_CHARI:
           word_code[0] = OPCODE_SET | (re->next_term++ << OPCODE_ARG_SHIFT);
           SET0(word_code + 1);
           SETBIT(word_code + 1, code[1]);
           if (code[0] == OP_CHARI) {
               SETBIT(word_code + 1, (PRIV(default_tables) + fcc_offset)[code[1]]);
           }
           word_code += 9;
           code += 2;
           break;

       case OP_NOT:
       case OP_NOTI:
           word_code[0] = OPCODE_SET | (re->next_term++ << OPCODE_ARG_SHIFT);
           SET1(word_code + 1);
           RESETBIT(word_code + 1, code[1]);
           if (code[0] == OP_NOTI) {
               RESETBIT(word_code + 1, (PRIV(default_tables) + fcc_offset)[code[1]]);
           }
           word_code += 9;
           code += 2;
           break;

       case OP_CLASS:
       case OP_NCLASS:
           word_code[0] = OPCODE_SET | (re->next_term++ << OPCODE_ARG_SHIFT);
           memcpy(word_code + 1, code + 1, 32);
           word_code += 9;
           code += 1 + 32 / sizeof(pcre_uchar);
           break;
       }
   }
   return word_code;
}

#if defined MPM_VERBOSE && MPM_VERBOSE
static void print_character(int character)
{
    if (character >= 0x20 && character <= 0x7f)
        printf("%c", character);
    else if (character <= 0xf)
        printf("\\x0%x", character);
    else
        printf("\\x%x", character);
}

static void print_bitset(uint8_t *bitset)
{
    int bit = 0x1;
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

int mpm_add(mpm_re *re, char *pattern, int flags)
{
    pcre *pcre_re;
    const char *errptr;
    int erroffset, size;
    int options = PCRE_NEWLINE_CRLF | PCRE_BSR_ANYCRLF | PCRE_NO_AUTO_CAPTURE;
    REAL_PCRE *real_pcre_re;
    pcre_uchar *start;
    uint32_t *word_code;
    mpm_re_pattern *re_pattern;

    if (flags & MPM_ADD_CASELESS)
        options |= PCRE_CASELESS;
    if (flags & MPM_ADD_MULTILINE)
        options |= PCRE_MULTILINE;
    if (flags & MPM_ADD_DOTALL)
        options |= PCRE_DOTALL;
    if (flags & MPM_ADD_EXTENDED)
        options |= PCRE_EXTENDED;

    pcre_re = pcre_compile(pattern, options, &errptr, &erroffset, NULL);
    if (!pcre_re)
        return MPM_INVALID_PATTERN;

    /* Process the internal representation of PCRE. */
    real_pcre_re = (REAL_PCRE *)pcre_re;

    if (real_pcre_re->magic_number != MAGIC_NUMBER
            || (real_pcre_re->options & (PCRE_UTF8 | PCRE_UCP))
            || ((real_pcre_re->options & 0x00700000) != PCRE_NEWLINE_CRLF)
            || ((real_pcre_re->options & 0x01800000) != PCRE_BSR_ANYCRLF)) {
        /* This should never happen in practice, so we return
           with an invalid pattern. */
        pcre_free(pcre_re);
        return MPM_INVALID_PATTERN;
    }

    start = (pcre_uchar *)real_pcre_re + real_pcre_re->name_table_offset
        + real_pcre_re->name_count * real_pcre_re->name_entry_size;

    /* We do two passes over the internal representation. */

    /* Calculate the length of the output. */
    size = get_dfa_size(start + 1 + LINK_SIZE, start + GET(start, 1));
    if (size < 0) {
        pcre_free(pcre_re);
        return MPM_UNSUPPORTED_PATTERN;
    }

    /* Generate the regular expression. */
    re_pattern = (mpm_re_pattern *)malloc(sizeof(mpm_re_pattern) + size * sizeof(uint32_t));
    if (!re_pattern) {
        pcre_free(pcre_re);
        return MPM_NO_MEMORY;
    }

    word_code = generate_dfa(re, re_pattern->word_code, start + 1 + LINK_SIZE, start + GET(start, 1));
    /* The definition reserves one word_code all the time, and
       we use it for the END opcode. */
    word_code[0] = OPCODE_END | ((re->next_id++ - 1) << OPCODE_ARG_SHIFT);

    if (word_code != re_pattern->word_code + size) {
        free(re_pattern);
        pcre_free(pcre_re);
        return MPM_INTERNAL_ERROR;
    }

    /* Insert the pattern. */
    re_pattern->next = re->patterns;
    re->patterns = re_pattern;

#if defined MPM_VERBOSE && MPM_VERBOSE
    word_code = re_pattern->word_code;
    printf("DFA representation of /%s/%s%s%s%s\n", pattern,
        (flags & MPM_ADD_CASELESS) ? "i" : "",
        (flags & MPM_ADD_MULTILINE) ? "m" : "",
        (flags & MPM_ADD_DOTALL) ? "d" : "",
        (flags & MPM_ADD_EXTENDED) ? "x" : "");

    do {
        printf("%4d: ", (int)(word_code - re_pattern->word_code));
        switch (word_code[0] & OPCODE_MASK) {
        case OPCODE_SET:
            printf("[");
            print_bitset((uint8_t *)(word_code + 1));
            printf("] (term:%d)\n", word_code[0] >> OPCODE_ARG_SHIFT);
            word_code += 9;
            break;
        }
    } while ((word_code[0] & OPCODE_MASK) != OPCODE_END);
    printf("%4d: END (id:%d)\n\n", (int)(word_code - re_pattern->word_code),
        word_code[0] >> OPCODE_ARG_SHIFT);
#endif

    pcre_free(pcre_re);
    return MPM_NO_ERROR;
}
