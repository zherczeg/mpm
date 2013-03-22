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

#ifndef mpm_internal_h
#define mpm_internal_h

/* Must be the first include, since it must not depend on other header files. */
#include "mpm.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "mpm_pcre.h"

/* Verbose compilation. */
#define MPM_VERBOSE 1

/* Get the length of the fixed size value. */
#define GET_FIXED_SIZE(flags)  (((flags) >> 8) & 0xffff)

/* Maximum number of regular expressions. */
#define PATTERN_LIMIT          32

/* Maximum number of states. */
#define STATE_LIMIT            20000

/* Eight, 32 bit words. */
#define CHAR_SET_SIZE          8
/* A non-valid ID or offset. */
#define DFA_NO_DATA            ((mpm_uint32)-1)

#define TOSTRING_IMPL(exp)     #exp
#define TOSTRING(exp)          TOSTRING_IMPL(exp)

/* Opcode flags. */
#define OPCODE_MASK            0x7
#define OPCODE_ARG_SHIFT       4
#define OPCODE_MARKED          0x8

/* OPCODE_END. */
#define OPCODE_END             0
/* OPCODE_SET, 32 byte long bit mask (same as eight mpm_uint32). */
#define OPCODE_SET             1
/* OPCODE_JUMP | (INDEX << OPCODE_ARG_SHIFT) */
#define OPCODE_JUMP            2
/* OPCODE_BRANCH | (INDEX << OPCODE_ARG_SHIFT) */
#define OPCODE_BRANCH          3

/* These two flags cannot be set in the same time. */
#define PATTERN_ANCHORED       0x1
#define PATTERN_MULTILINE      0x2

/* A DFA representation of a pattern */
typedef struct mpm_re_pattern {
    struct mpm_re_pattern *next;
    mpm_uint32 flags;
    mpm_uint32 term_range_start;
    mpm_uint32 term_range_size;
    mpm_uint32 word_code[1];
} mpm_re_pattern;

#define RE_MODE_COMPILE        0x1
/* Midify mpm_exec4 if you change this constant. */
#define RE_CHAR_SET_256        0x2

/* Internal representation of the regular expression. */
struct mpm_re_internal {
    /* These members are used by mpm_add(). */
    mpm_uint32 flags;
    union {
        struct {
            mpm_re_pattern *patterns;
            mpm_uint32 next_id;
            mpm_uint32 next_term_index;
        } compile;
        struct {
            mpm_uint8* compiled_pattern;
            mpm_uint32 non_newline_offset;
            mpm_uint32 newline_offset;
        } run;
    };
};

struct pattern_data;

/* Each pattern set contains an mpm_re or a pcre pattern. */
typedef struct pattern_list_item {
    mpm_uint16 *rule_indices;
    union {
        mpm_uint32 priority;
        void *pcre;
    } u1;
    union {
        struct pattern_data *pattern;
        mpm_re *re;
        void *pcre_study;
    } u2;
} pattern_list_item;

struct mpm_rule_list_internal {
    mpm_uint16 *rule_indices;
    mpm_size pattern_list_length;
    mpm_size rule_count;
    mpm_uint32 result_length;
    mpm_uint32 result_last_word;
    pattern_list_item pattern_list[1];
};

#define CHARSET_CLEAR(set)          memset((set), 0x00, 32)
#define CHARSET_SET(set)            memset((set), 0xff, 32)
#define CHARSET_GETBIT(set, bit)    (((mpm_uint8*)(set))[(bit) >> 3] & (1 << ((bit) & 0x7)))
#define CHARSET_CLEARBIT(set, bit)  (((mpm_uint8*)(set))[(bit) >> 3] &= ~(1 << ((bit) & 0x7)))
#define CHARSET_SETBIT(set, bit)    (((mpm_uint8*)(set))[(bit) >> 3] |= (1 << ((bit) & 0x7)))

/* mpm_uint32 based bitset is used, but we need to avoid issues with alignment. */
#define DFA_SETBIT(set, bit)        ((set)[(bit) >> 5] |= (1 << ((bit) & 0x1f)))
#define DFA_GET_BIT(set, bit)       ((set)[(bit) >> 5] & (1 << ((bit) & 0x1f)))

/* Rule set flags. */
#define RULE_LIST_END          ((mpm_uint16)-1)
#define PATTERN_LIST_END       ((mpm_uint16)-2)

/* Private, shared functions. */
int mpm_private_rating(mpm_re_pattern *pattern);
void mpm_private_free_patterns(mpm_re_pattern *pattern);

#if defined MPM_VERBOSE && MPM_VERBOSE
void mpm_print_char_range(mpm_uint8 *bitset);
#endif

#endif // mpm_internal_h
