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
static int get_dfa_bracket_size(pcre_uchar *code, pcre_uchar **bracket_end);

static int get_dfa_size(pcre_uchar *code, pcre_uchar *end)
{
    int size = 0, subexpression_size;

    while (code < end) {
        switch (code[0]) {
        case OP_NOT_DIGIT:
        case OP_DIGIT:
        case OP_NOT_WHITESPACE:
        case OP_WHITESPACE:
        case OP_NOT_WORDCHAR:
        case OP_WORDCHAR:
        case OP_ANY:
        case OP_ALLANY:
        case OP_NOT_HSPACE:
        case OP_HSPACE:
        case OP_NOT_VSPACE:
        case OP_VSPACE:
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

        case OP_STAR:
        case OP_MINSTAR:
        case OP_STARI:
        case OP_MINSTARI:
        case OP_NOTSTAR:
        case OP_NOTMINSTAR:
        case OP_NOTSTARI:
        case OP_NOTMINSTARI:
            size += 9 + 2;
            code += 2;
            break;

        case OP_PLUS:
        case OP_MINPLUS:
        case OP_QUERY:
        case OP_MINQUERY:
        case OP_PLUSI:
        case OP_MINPLUSI:
        case OP_QUERYI:
        case OP_MINQUERYI:
        case OP_NOTPLUS:
        case OP_NOTMINPLUS:
        case OP_NOTQUERY:
        case OP_NOTMINQUERY:
        case OP_NOTPLUSI:
        case OP_NOTMINPLUSI:
        case OP_NOTQUERYI:
        case OP_NOTMINQUERYI:
            size += 9 + 1;
            code += 2;
            break;

        case OP_UPTO:
        case OP_MINUPTO:
        case OP_UPTOI:
        case OP_MINUPTOI:
        case OP_NOTUPTO:
        case OP_NOTMINUPTO:
        case OP_NOTUPTOI:
        case OP_NOTMINUPTOI:
            size += (9 + 1) * GET2(code, 1);
            code += 2 + IMM2_SIZE;
            break;

        case OP_EXACT:
        case OP_EXACTI:
        case OP_NOTEXACT:
        case OP_NOTEXACTI:
            size += 9 * GET2(code, 1);
            code += 2 + IMM2_SIZE;
            break;

        case OP_TYPESTAR:
        case OP_TYPEMINSTAR:
        case OP_CRSTAR:
        case OP_CRMINSTAR:
            /* We defer the type check. */
            size += 2;
            code++;
            break;

        case OP_TYPEPLUS:
        case OP_TYPEMINPLUS:
        case OP_TYPEQUERY:
        case OP_TYPEMINQUERY:
        case OP_CRPLUS:
        case OP_CRMINPLUS:
        case OP_CRQUERY:
        case OP_CRMINQUERY:
            /* We defer the type check. */
            size++;
            code++;
            break;

        case OP_TYPEUPTO:
        case OP_TYPEMINUPTO:
            size += ((9 + 1) * GET2(code, 1)) - 9;
            code += 1 + IMM2_SIZE;
            break;

        case OP_TYPEEXACT:
            size += (9 * GET2(code, 1)) - 9;
            code += 1 + IMM2_SIZE;
            break;

        case OP_CRRANGE:
        case OP_CRMINRANGE:
            size += 9 * GET2(code, 1);
            if (GET2(code, 1 + IMM2_SIZE) > 0)
                size += 10 * (GET2(code, 1 + IMM2_SIZE) - GET2(code, 1));
            else
                size++;
            size -= 9;
            code += 1 + 2 * IMM2_SIZE;
            break;

        case OP_CLASS:
        case OP_NCLASS:
            size += 9;
            code += 1 + 32 / sizeof(pcre_uchar);
            break;

        case OP_BRA:
        case OP_SBRA:
        case OP_BRAZERO:
        case OP_BRAMINZERO:
            subexpression_size = get_dfa_bracket_size(code, &code);
            if (subexpression_size < 0)
                return -1;
            size += subexpression_size;
            break;

        default:
            return -1;
        }
    }
    return size;
}

static int get_dfa_bracket_size(pcre_uchar *code, pcre_uchar **bracket_end)
{
    int size = 0, subexpression_size;
    pcre_uchar *next_alternative;

    if (code[0] == OP_BRAZERO || code[0] == OP_BRAMINZERO) {
        size++;
        code++;
    }

    if (code[0] != OP_BRA && code[0] != OP_SBRA)
        return -1;

    next_alternative = code + GET(code, 1);
    code += 1 + LINK_SIZE;
    while (*next_alternative == OP_ALT) {
        subexpression_size = get_dfa_size(code, next_alternative);
        if (subexpression_size < 0)
            return -1;
        size += subexpression_size + 2;
        code = next_alternative;
        next_alternative = code + GET(code, 1);
        code += 1 + LINK_SIZE;
    }

    subexpression_size = get_dfa_size(code, next_alternative);
    if (subexpression_size < 0)
        return -1;
    size += subexpression_size;

    if (next_alternative[0] == OP_KETRMAX || next_alternative[0] == OP_KETRMIN)
        size++;

    if (bracket_end)
        *bracket_end = next_alternative + 1 + LINK_SIZE;
    return size;
}

/* Character set generators. */
static void generate_set(mpm_re *re, uint32_t *word_code, int opcode, pcre_uchar *code)
{
    word_code[0] = OPCODE_SET | (re->next_term++ << OPCODE_ARG_SHIFT);
    int i;

    switch (opcode) {
    case OP_NOT_DIGIT:
        memcpy(word_code + 1, PRIV(default_tables) + cbits_offset + cbit_digit, 32);
        break;

    case OP_DIGIT:
        memcpy(word_code + 1, PRIV(default_tables) + cbits_offset + cbit_digit, 32);
        return;

    case OP_NOT_WHITESPACE:
        memcpy(word_code + 1, PRIV(default_tables) + cbits_offset + cbit_space, 32);
        break;

    case OP_WHITESPACE:
        memcpy(word_code + 1, PRIV(default_tables) + cbits_offset + cbit_space, 32);
        return;

    case OP_NOT_WORDCHAR:
        memcpy(word_code + 1, PRIV(default_tables) + cbits_offset + cbit_word, 32);
        break;

    case OP_WORDCHAR:
        memcpy(word_code + 1, PRIV(default_tables) + cbits_offset + cbit_word, 32);
        return;

    case OP_ANY:
    case OP_ALLANY:
        SET1(word_code + 1);
        if (opcode == OP_ANY) {
            RESETBIT(word_code + 1, '\r');
            RESETBIT(word_code + 1, '\n');
        }
        return;

    case OP_NOT_HSPACE:
        SET1(word_code + 1);
        RESETBIT(word_code + 1, 0x09);
        RESETBIT(word_code + 1, 0x20);
        RESETBIT(word_code + 1, 0xa0);
        return;

    case OP_HSPACE:
        SET0(word_code + 1);
        SETBIT(word_code + 1, 0x09);
        SETBIT(word_code + 1, 0x20);
        SETBIT(word_code + 1, 0xa0);
        return;

    case OP_NOT_VSPACE:
        SET1(word_code + 1);
        /* 0x0a - 0x0d */
        ((uint8_t*)(word_code + 1))[1] &= ~0x3c;
        RESETBIT(word_code + 1, 0x85);
        return;

    case OP_VSPACE:
        SET0(word_code + 1);
        /* 0x0a - 0x0d */
        ((uint8_t*)(word_code + 1))[1] |= 0x3c;
        SETBIT(word_code + 1, 0x85);
        return;

    case OP_CHAR:
    case OP_CHARI:
        SET0(word_code + 1);
        SETBIT(word_code + 1, code[0]);
        if (opcode == OP_CHARI) {
            SETBIT(word_code + 1, (PRIV(default_tables) + fcc_offset)[code[0]]);
        }
        return;

    case OP_NOT:
    case OP_NOTI:
        SET1(word_code + 1);
        RESETBIT(word_code + 1, code[0]);
        if (opcode == OP_NOTI) {
            RESETBIT(word_code + 1, (PRIV(default_tables) + fcc_offset)[code[0]]);
        }
        return;

    case OP_CLASS:
    case OP_NCLASS:
        memcpy(word_code + 1, code, 32);
        return;
    }

    /* Invert the bitset. We can invert words, since the alignment does
       not affect the result. */
    for (i = 1; i < 9; i++)
         word_code[i] = ~word_code[i];
}

static uint32_t * generate_repeat(mpm_re *re, uint32_t *word_code, int opcode,
    pcre_uchar *code, int min, int max)
{
    uint32_t *repeat_start;

    if (min == 0) {
        if (max == 0) {
            word_code[0] = OPCODE_BRANCH | (uint32_t)11 << OPCODE_ARG_SHIFT;
            generate_set(re, word_code + 1, opcode, code);
            word_code[10] = OPCODE_BRANCH | (uint32_t)-9 << OPCODE_ARG_SHIFT;
            return word_code + 11;
        }

        word_code[0] = OPCODE_BRANCH | (uint32_t)(max * 10) << OPCODE_ARG_SHIFT;
        generate_set(re, word_code + 1, opcode, code);
        repeat_start = word_code + 2;
        word_code += 10;
        max--;
        while (max > 0) {
            word_code[0] = OPCODE_BRANCH | (uint32_t)(max * 10) << OPCODE_ARG_SHIFT;
            word_code[1] = OPCODE_SET | (re->next_term++ << OPCODE_ARG_SHIFT);
            memcpy(word_code + 2, repeat_start, 8 * sizeof(uint32_t));
            word_code += 10;
            max--;
        }
        return word_code;
    }

    generate_set(re, word_code, opcode, code);
    repeat_start = word_code + 1;
    word_code += 9;
    min--;
    max--;
    while (min > 0) {
        word_code[0] = OPCODE_SET | (re->next_term++ << OPCODE_ARG_SHIFT);
        memcpy(word_code + 1, repeat_start, 8 * sizeof(uint32_t));
        word_code += 9;
        min--;
        max--;
    }

    if (max < 0) {
        /* Since max was 0 or >= min before, this case is only possible
           if max was 0. */
        word_code[0] = OPCODE_BRANCH | (uint32_t)-9 << OPCODE_ARG_SHIFT;
        return word_code + 1;
    }

    while (max > 0) {
        word_code[0] = OPCODE_BRANCH | (uint32_t)(max * 10) << OPCODE_ARG_SHIFT;
        word_code[1] = OPCODE_SET | (re->next_term++ << OPCODE_ARG_SHIFT);
        memcpy(word_code + 2, repeat_start, 8 * sizeof(uint32_t));
        word_code += 10;
        max--;
    }
    return word_code;
}

static uint32_t * generate_char_repeat(mpm_re *re, uint32_t *word_code, pcre_uchar *code)
{
    int min, max, opcode, type;
    pcre_uchar *offset;

    if (code[0] >= OP_STAR && code[0] <= OP_EXACT) {
        type = code[0];
        opcode = OP_CHAR;
    } else if (code[0] >= OP_STARI && code[0] <= OP_EXACTI) {
        type = code[0] - (OP_STARI - OP_STAR);
        opcode = OP_CHARI;
    } else if (code[0] >= OP_NOTSTAR && code[0] <= OP_NOTEXACT) {
        type = code[0] - (OP_NOTSTAR - OP_STAR);
        opcode = OP_NOT;
    } else if (code[0] >= OP_NOTSTARI && code[0] <= OP_NOTEXACTI) {
        type = code[0] - (OP_NOTSTARI - OP_STAR);
        opcode = OP_NOTI;
    } else if (code[0] >= OP_TYPESTAR && code[0] <= OP_TYPEEXACT) {
        type = code[0] - (OP_TYPESTAR - OP_STAR);
        opcode = (code[0] <= OP_TYPEMINQUERY) ? code[1] : code[1 + IMM2_SIZE];
    }

    switch (type) {
    case OP_STAR:
    case OP_MINSTAR:
        min = 0;
        max = 0;
        offset = code + 1;
        break;

    case OP_PLUS:
    case OP_MINPLUS:
        min = 1;
        max = 0;
        offset = code + 1;
        break;

    case OP_QUERY:
    case OP_MINQUERY:
        min = 0;
        max = 1;
        offset = code + 1;
        break;

    case OP_UPTO:
    case OP_MINUPTO:
        min = 0;
        max = GET2(code, 1);
        offset = code + 1 + IMM2_SIZE;
        break;

    case OP_EXACT:
        min = GET2(code, 1);
        max = min;
        offset = code + 1 + IMM2_SIZE;
        break;
    }

    return generate_repeat(re, word_code, opcode, offset, min, max);
}

static uint32_t * generate_range_repeat(mpm_re *re, uint32_t *word_code, pcre_uchar *code)
{
    int min, max;

    switch (code[1 + 32 / sizeof(pcre_uchar)]) {
    case OP_CRSTAR:
    case OP_CRMINSTAR:
        min = 0;
        max = 0;
        break;

    case OP_CRPLUS:
    case OP_CRMINPLUS:
        min = 1;
        max = 0;
        break;

    case OP_CRQUERY:
    case OP_CRMINQUERY:
        min = 0;
        max = 1;
        break;

    case OP_CRRANGE:
    case OP_CRMINRANGE:
        min = GET2(code, 2 + 32 / sizeof(pcre_uchar));
        max = GET2(code, 2 + 32 / sizeof(pcre_uchar) + IMM2_SIZE);
        break;
    }

    return generate_repeat(re, word_code, code[0], code + 1, min, max);
}

/* Recursive function to generate the DFA representation. */
static uint32_t * generate_dfa_bracket(mpm_re *re, uint32_t *word_code,
    pcre_uchar *code, pcre_uchar **bracket_end);

static uint32_t * generate_dfa(mpm_re *re, uint32_t *word_code,
    pcre_uchar *code, pcre_uchar *end)
{
    pcre_uchar repeat;

    while (code < end) {
        switch (code[0]) {
        case OP_ANY:
        case OP_ALLANY:
        case OP_NOT_DIGIT:
        case OP_DIGIT:
        case OP_NOT_WHITESPACE:
        case OP_WHITESPACE:
        case OP_NOT_WORDCHAR:
        case OP_WORDCHAR:
        case OP_NOT_HSPACE:
        case OP_HSPACE:
        case OP_NOT_VSPACE:
        case OP_VSPACE:
            generate_set(re, word_code, code[0], NULL);
            word_code += 9;
            code++;
            break;

        case OP_CHAR:
        case OP_CHARI:
        case OP_NOT:
        case OP_NOTI:
            generate_set(re, word_code, code[0], code + 1);
            word_code += 9;
            code += 2;
            break;

        case OP_STAR:
        case OP_MINSTAR:
        case OP_PLUS:
        case OP_MINPLUS:
        case OP_QUERY:
        case OP_MINQUERY:
        case OP_STARI:
        case OP_MINSTARI:
        case OP_PLUSI:
        case OP_MINPLUSI:
        case OP_QUERYI:
        case OP_MINQUERYI:
        case OP_NOTSTAR:
        case OP_NOTMINSTAR:
        case OP_NOTPLUS:
        case OP_NOTMINPLUS:
        case OP_NOTQUERY:
        case OP_NOTMINQUERY:
        case OP_NOTSTARI:
        case OP_NOTMINSTARI:
        case OP_NOTPLUSI:
        case OP_NOTMINPLUSI:
        case OP_NOTQUERYI:
        case OP_NOTMINQUERYI:
        case OP_TYPESTAR:
        case OP_TYPEMINSTAR:
        case OP_TYPEPLUS:
        case OP_TYPEMINPLUS:
        case OP_TYPEQUERY:
        case OP_TYPEMINQUERY:
            word_code = generate_char_repeat(re, word_code, code);
            code += 2;
            break;

        case OP_UPTO:
        case OP_MINUPTO:
        case OP_EXACT:
        case OP_UPTOI:
        case OP_MINUPTOI:
        case OP_EXACTI:
        case OP_NOTUPTO:
        case OP_NOTMINUPTO:
        case OP_NOTEXACT:
        case OP_NOTUPTOI:
        case OP_NOTMINUPTOI:
        case OP_NOTEXACTI:
        case OP_TYPEUPTO:
        case OP_TYPEMINUPTO:
        case OP_TYPEEXACT:
            word_code = generate_char_repeat(re, word_code, code);
            code += 2 + IMM2_SIZE;
            break;

        case OP_CLASS:
        case OP_NCLASS:
            repeat = code[1 + 32 / sizeof(pcre_uchar)];
            if (repeat >= OP_CRSTAR && repeat <= OP_CRMINRANGE) {
                word_code = generate_range_repeat(re, word_code, code);
                code += 2 + 32 / sizeof(pcre_uchar) + (repeat >= OP_CRRANGE ? 2 * IMM2_SIZE : 0);
            } else {
                generate_set(re, word_code, code[0], code + 1);
                word_code += 9;
                code += 1 + 32 / sizeof(pcre_uchar);
            }
            break;

        case OP_BRA:
        case OP_SBRA:
        case OP_BRAZERO:
        case OP_BRAMINZERO:
            word_code = generate_dfa_bracket(re, word_code, code, &code);
            break;
        }
    }
    return word_code;
}

static uint32_t * generate_dfa_bracket(mpm_re *re, uint32_t *word_code,
    pcre_uchar *code, pcre_uchar **bracket_end)
{
    uint32_t *question_mark = NULL;
    uint32_t *first_alternative;
    uint32_t *previous_alternative;
    uint32_t *previous_jump = NULL;
    pcre_uchar *next_alternative;
    uint32_t delta;

    if (code[0] == OP_BRAZERO || code[0] == OP_BRAMINZERO) {
        question_mark = word_code;
        word_code++;
        code++;
    }

    first_alternative = word_code;

    next_alternative = code + GET(code, 1);
    code += 1 + LINK_SIZE;
    while (*next_alternative == OP_ALT) {
        previous_alternative = word_code;
        word_code++;
        word_code = generate_dfa(re, word_code, code, next_alternative);

        if (!previous_jump)
            previous_jump = word_code;
        word_code[0] = (uint32_t)(word_code - previous_jump);
        previous_jump = word_code;
        word_code++;

        previous_alternative[0] = OPCODE_BRANCH | (uint32_t)(word_code - previous_alternative) << OPCODE_ARG_SHIFT;

        code = next_alternative;
        next_alternative = code + GET(code, 1);
        code += 1 + LINK_SIZE;
    }

    word_code = generate_dfa(re, word_code, code, next_alternative);

    if (next_alternative[0] == OP_KETRMAX || next_alternative[0] == OP_KETRMIN) {
        word_code[0] = OPCODE_BRANCH | (uint32_t)(first_alternative - word_code) << OPCODE_ARG_SHIFT;
        word_code++;
    }

    if (question_mark)
        question_mark[0] = OPCODE_BRANCH | (uint32_t)(word_code - question_mark) << OPCODE_ARG_SHIFT;

    if (previous_jump) {
        do {
            delta = *previous_jump;
            previous_jump[0] = OPCODE_JUMP | (uint32_t)(word_code - previous_jump) << OPCODE_ARG_SHIFT;
            previous_jump -= delta;
        } while (delta > 0);
    }

    if (bracket_end)
        *bracket_end = next_alternative + 1 + LINK_SIZE;
    return word_code;
}

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
    size = get_dfa_bracket_size(start, NULL);
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

    word_code = generate_dfa_bracket(re, re_pattern->word_code, start, NULL);
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
    if (flags & MPM_ADD_VERBOSE) {
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

            case OPCODE_JUMP:
            case OPCODE_BRANCH:
                size = (int32_t)(word_code[0]) >> OPCODE_ARG_SHIFT;
                printf("%s TO %d (%s%d)\n", (word_code[0] & OPCODE_MASK) == OPCODE_JUMP ? "JUMP" : "BRANCH",
                    (int)(word_code - re_pattern->word_code) + size, size >= 0 ? "+" : "", size);
                word_code ++;
                break;
            }
        } while ((word_code[0] & OPCODE_MASK) != OPCODE_END);
        printf("%4d: END (id:%d)\n\n", (int)(word_code - re_pattern->word_code),
            word_code[0] >> OPCODE_ARG_SHIFT);
    }
#endif

    pcre_free(pcre_re);
    return MPM_NO_ERROR;
}
