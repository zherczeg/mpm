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
#include "mpm_pcre.h"

/* Verbose compilation. */
#define MPM_VERBOSE 1

#define OPCODE_MASK         0x7
#define OPCODE_ARG_SHIFT    4
#define OPCODE_MARKED       0x8

/* OPCODE_END. */
#define OPCODE_END          0
/* OPCODE_SET, 32 byte long bit mask (same as eight uint32_t). */
#define OPCODE_SET          1
/* OPCODE_JUMP | (INDEX << OPCODE_ARG_SHIFT) */
#define OPCODE_JUMP         2
/* OPCODE_BRANCH | (INDEX << OPCODE_ARG_SHIFT) */
#define OPCODE_BRANCH       3

/* DFA manipulation macros. */
#define DFA_IS_END_STATE(x)    ((x) & 0x1)
#define DFA_SET_END_STATE(x)   ((x) |= 0x1)
#define DFA_GET_OFFSET(x)      ((x) >> 1)
#define DFA_SET_OFFSET(x, y)   ((x) = ((uint32_t)(y) << 1))

/* A DFA representation of a pattern */
typedef struct mpm_re_pattern_internal {
    struct mpm_re_pattern_internal *next;
    uint32_t term_range_start;
    uint32_t term_range_size;
    uint32_t word_code[1];
} mpm_re_pattern;

/* Internal representation of the regular expression. */
struct mpm_re_internal {
    /* These members are used by mpm_add(). */
    uint32_t next_id;
    uint32_t next_term_index;
    mpm_re_pattern *patterns;
};

#define SET0(set)           memset((set), 0x00, 32)
#define SET1(set)           memset((set), 0xff, 32)
#define SETBIT(set, bit)    (((uint8_t*)(set))[(bit) >> 3] |= (1 << ((bit) & 0x7)))
#define RESETBIT(set, bit)  (((uint8_t*)(set))[(bit) >> 3] &= ~(1 << ((bit) & 0x7)))

#endif // mpm_internal_h
