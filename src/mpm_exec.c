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
/*                           NFA generator functions.                      */
/* ----------------------------------------------------------------------- */

#define GET_END_STATES(map) \
    (((mpm_uint32*)(map))[-1])

#define GET_NEXT_OFFSET(map, offset, index) \
    (((int32_t*)((map) + (offset)))[index])

#define NEXT_STATE_MAP(map, offset) \
    ((map) + (offset))

int mpm_exec(mpm_re *re, mpm_char8 *subject, mpm_size length, mpm_size offset, mpm_uint32 *result)
{
    mpm_uint32 current_character;
    mpm_uint8 *state_map;
    int32_t next_offset;
    mpm_uint32 current_result;
    mpm_uint32 end_states;

    if (re->flags & RE_MODE_COMPILE)
        return MPM_RE_IS_NOT_COMPILED;

    length -= offset;
    subject += offset;
    if (length == 0) {
        result[0] = 0;
        return MPM_NO_ERROR;
    }

    /* Simple matcher. */
    state_map = re->run.compiled_pattern + sizeof(mpm_uint32);
    current_result = 0;
    if (offset > 0) {
        if (subject[-1] == '\n' || subject[-1] == '\r')
            state_map += re->run.newline_offset;
        else
            state_map += re->run.non_newline_offset;
    }

    if (!(re->flags & RE_CHAR_SET_256)) {
        do {
            /* The squence is optimized for performance. */
            current_character = *(mpm_uint8 *)subject;
            next_offset = state_map[current_character <= 127 ? current_character : 127];
            end_states = GET_END_STATES(state_map);
            next_offset = GET_NEXT_OFFSET(state_map, 128, next_offset);
            subject++;
            current_result |= end_states;
            state_map = NEXT_STATE_MAP(state_map, next_offset);
        } while (--length);
    } else {
        do {
            /* The squence is optimized for performance. */
            current_character = *(mpm_uint8 *)subject;
            next_offset = state_map[current_character];
            end_states = GET_END_STATES(state_map);
            next_offset = GET_NEXT_OFFSET(state_map, 256, next_offset);
            subject++;
            current_result |= end_states;
            state_map = NEXT_STATE_MAP(state_map, next_offset);
        } while (--length);
    }

    result[0] = current_result | GET_END_STATES(state_map);
    return MPM_NO_ERROR;
}

#define EXEC4_MAIN_LOOP(TEST0, LEN0, TEST1, LEN1, TEST2, LEN2, TEST3, LEN3) \
    do { \
        /* The squence is optimized for performance. */ \
        current_character = *(mpm_uint8 *)subject; \
        next_offset0 = state_map0[(TEST0)]; \
        next_offset1 = state_map1[(TEST1)]; \
        next_offset2 = state_map2[(TEST2)]; \
        next_offset3 = state_map3[(TEST3)]; \
        end_states0 = GET_END_STATES(state_map0); \
        end_states1 = GET_END_STATES(state_map1); \
        end_states2 = GET_END_STATES(state_map2); \
        end_states3 = GET_END_STATES(state_map3); \
        next_offset0 = GET_NEXT_OFFSET(state_map0, (LEN0), next_offset0); \
        next_offset1 = GET_NEXT_OFFSET(state_map1, (LEN1), next_offset1); \
        next_offset2 = GET_NEXT_OFFSET(state_map2, (LEN2), next_offset2); \
        next_offset3 = GET_NEXT_OFFSET(state_map3, (LEN3), next_offset3); \
        subject++; \
        current_result0 |= end_states0; \
        current_result1 |= end_states1; \
        current_result2 |= end_states2; \
        current_result3 |= end_states3; \
        state_map0 = NEXT_STATE_MAP(state_map0, next_offset0); \
        state_map1 = NEXT_STATE_MAP(state_map1, next_offset1); \
        state_map2 = NEXT_STATE_MAP(state_map2, next_offset2); \
        state_map3 = NEXT_STATE_MAP(state_map3, next_offset3); \
    } while (--length);

#define T128 (current_character <= 127) ? current_character : 127
#define T256 current_character

int mpm_exec4(mpm_re **re, mpm_char8 *subject, mpm_size length, mpm_size offset, mpm_uint32 *results)
{
    mpm_uint32 current_character;
    mpm_uint8 *state_map0, *state_map1, *state_map2, *state_map3;
    int32_t next_offset0, next_offset1, next_offset2, next_offset3;
    mpm_uint32 current_result0, current_result1, current_result2, current_result3;
    mpm_uint32 end_states0, end_states1, end_states2, end_states3;

    if ((re[0]->flags & RE_MODE_COMPILE) || (re[1]->flags & RE_MODE_COMPILE)
            || (re[2]->flags & RE_MODE_COMPILE) || (re[3]->flags & RE_MODE_COMPILE))
        return MPM_RE_IS_NOT_COMPILED;

    length -= offset;
    subject += offset;
    if (length == 0) {
        results[0] = 0;
        results[1] = 0;
        results[2] = 0;
        results[3] = 0;
        return MPM_NO_ERROR;
    }

    /* Simple matcher. */
    state_map0 = re[0]->run.compiled_pattern + sizeof(mpm_uint32);
    state_map1 = re[1]->run.compiled_pattern + sizeof(mpm_uint32);
    state_map2 = re[2]->run.compiled_pattern + sizeof(mpm_uint32);
    state_map3 = re[3]->run.compiled_pattern + sizeof(mpm_uint32);
    current_result0 = 0;
    current_result1 = 0;
    current_result2 = 0;
    current_result3 = 0;
    if (offset > 0) {
        if (subject[-1] == '\n' || subject[-1] == '\r') {
            state_map0 += re[0]->run.newline_offset;
            state_map1 += re[1]->run.newline_offset;
            state_map2 += re[2]->run.newline_offset;
            state_map3 += re[3]->run.newline_offset;
        } else {
            state_map0 += re[0]->run.non_newline_offset;
            state_map1 += re[1]->run.non_newline_offset;
            state_map2 += re[2]->run.non_newline_offset;
            state_map3 += re[3]->run.non_newline_offset;
        }
    }

    switch (((re[0]->flags & RE_CHAR_SET_256) >> 1)
            | (re[1]->flags & RE_CHAR_SET_256)
            | ((re[2]->flags & RE_CHAR_SET_256) << 1)
            | ((re[3]->flags & RE_CHAR_SET_256) << 2)) {
    case 0x0:
        EXEC4_MAIN_LOOP(T128, 128, T128, 128, T128, 128, T128, 128);
        break;
    case 0x1:
        EXEC4_MAIN_LOOP(T256, 256, T128, 128, T128, 128, T128, 128);
        break;
    case 0x2:
        EXEC4_MAIN_LOOP(T128, 128, T256, 256, T128, 128, T128, 128);
        break;
    case 0x3:
        EXEC4_MAIN_LOOP(T256, 256, T256, 256, T128, 128, T128, 128);
        break;
    case 0x4:
        EXEC4_MAIN_LOOP(T128, 128, T128, 128, T256, 256, T128, 128);
        break;
    case 0x5:
        EXEC4_MAIN_LOOP(T256, 256, T128, 128, T256, 256, T128, 128);
        break;
    case 0x6:
        EXEC4_MAIN_LOOP(T128, 128, T256, 256, T256, 256, T128, 128);
        break;
    case 0x7:
        EXEC4_MAIN_LOOP(T256, 256, T256, 256, T256, 256, T128, 128);
        break;
    case 0x8:
        EXEC4_MAIN_LOOP(T128, 128, T128, 128, T128, 128, T256, 256);
        break;
    case 0x9:
        EXEC4_MAIN_LOOP(T256, 256, T128, 128, T128, 128, T256, 256);
        break;
    case 0xa:
        EXEC4_MAIN_LOOP(T128, 128, T256, 256, T128, 128, T256, 256);
        break;
    case 0xb:
        EXEC4_MAIN_LOOP(T256, 256, T256, 256, T128, 128, T256, 256);
        break;
    case 0xc:
        EXEC4_MAIN_LOOP(T128, 128, T128, 128, T256, 256, T256, 256);
        break;
    case 0xd:
        EXEC4_MAIN_LOOP(T256, 256, T128, 128, T256, 256, T256, 256);
        break;
    case 0xe:
        EXEC4_MAIN_LOOP(T128, 128, T256, 256, T256, 256, T256, 256);
        break;
    case 0xf:
        EXEC4_MAIN_LOOP(T256, 256, T256, 256, T256, 256, T256, 256);
        break;
    }

    results[0] = current_result0 | GET_END_STATES(state_map0);
    results[1] = current_result1 | GET_END_STATES(state_map1);
    results[2] = current_result2 | GET_END_STATES(state_map2);
    results[3] = current_result3 | GET_END_STATES(state_map3);
    return MPM_NO_ERROR;
}

mpm_re * mpm_dummy_re(void)
{
    static mpm_char8 compiled_pattern[sizeof(mpm_uint32) + 128 + sizeof(mpm_uint32)];
    static mpm_re re;
    /* Thread safe assignment. */
    re.run.compiled_pattern = compiled_pattern;
    return &re;
}

/* A working PCRE is required from here.  */
#include "pcre.h"

int mpm_exec_list(mpm_rule_list *rule_list, mpm_char8 *subject, mpm_size length, mpm_size offset, mpm_uint32 *result, void *pcre_stack)
{
    /* A complex matching algortihm with several gotos. */
    pattern_list_item *next_pattern = rule_list->pattern_list;
    pattern_list_item *next_re_pattern = next_pattern;
    pattern_list_item *last_pattern = next_pattern + rule_list->pattern_list_length;
    mpm_size rule_count = rule_list->rule_count;
    mpm_re *re_list[4];
    pattern_list_item *pattern_list[4];
    pattern_list_item **pattern_list_last;
    pattern_list_item **pattern_list_next;
    mpm_uint32 re_result[4];
    mpm_uint32 *re_result_next;
    mpm_uint32 result_bits, current_bits, current_bit;
    mpm_re *dummy_re = mpm_dummy_re();
    mpm_uint16 *rule_indices;
    mpm_uint16 rule_index;
    int ovector[32];

    switch (rule_list->result_length) {
    case 0:
        result[0] = rule_list->result_last_word;
        break;

    case 4:
        result[0] = 0xffffffff;
        result[1] = rule_list->result_last_word;
        break;

    case 8:
        result[0] = 0xffffffff;
        result[1] = 0xffffffff;
        result[2] = rule_list->result_last_word;
        break;

    default:
        memset(result, 0xff, rule_list->result_length);
        result[rule_list->result_length >> 2] = rule_list->result_last_word;
        break;
    }

mainloop:
    while (1) {
        if (next_pattern >= last_pattern)
            return MPM_NO_ERROR;

        if (next_pattern->u1.pcre || next_pattern >= next_re_pattern) {
            rule_indices = next_pattern->rule_indices;
            while (1) {
                rule_index = *(--rule_indices);
                if (rule_index == RULE_LIST_END)
                    break;
                if (result[rule_index >> 5] & (1 << (rule_index & 0x1f))) {
                    if (next_pattern->u1.pcre)
                        goto pcre_match;
                    goto re_match;
                }
            }
        }
        next_pattern++;
    }

re_match:
    /* Searching at most 4 other patterns. */
    next_re_pattern = next_pattern + 1;
    pattern_list[0] = next_pattern;
    pattern_list_last = pattern_list + 1;
    next_pattern++;

    while (1) {
        if (next_re_pattern >= last_pattern)
            break;

        if (!next_re_pattern->u1.pcre) {
            rule_indices = next_pattern->rule_indices;
            while (1) {
                rule_index = *(--rule_indices);
                if (rule_index == RULE_LIST_END)
                    break;
                if (result[rule_index >> 5] & (1 << (rule_index & 0x1f))) {
                    *pattern_list_last++ = next_re_pattern;
                    if (pattern_list_last >= pattern_list + 4) {
                        if (!next_pattern->u1.pcre)
                            next_pattern++;
                        next_re_pattern++;
                        goto re_list_full;
                    }
                    break;
                }
            }
        }
        if (!next_pattern->u1.pcre)
            next_pattern++;
        next_re_pattern++;
    }
re_list_full:

    if (pattern_list_last == pattern_list + 1) {
        mpm_exec(pattern_list[0]->u2.re, subject, length, offset, re_result);
    } else {
        re_list[0] = pattern_list[0]->u2.re;
        re_list[1] = pattern_list[1]->u2.re;
        re_list[2] = (pattern_list_last > pattern_list + 2) ? pattern_list[2]->u2.re : dummy_re;
        re_list[3] = (pattern_list_last > pattern_list + 3) ? pattern_list[3]->u2.re : dummy_re;
        mpm_exec4(re_list, subject, length, offset, re_result);
    }

    pattern_list_next = pattern_list;
    re_result_next = re_result;
    while (1) {
        result_bits = *re_result_next++;
        rule_indices = pattern_list_next[0]->rule_indices;
        while (1) {
            if (result_bits & 0x1) {
                do {
                    rule_index = *rule_indices++;
                } while (rule_index < PATTERN_LIST_END);
            } else {
                while (1) {
                    rule_index = *rule_indices++;
                    if (rule_index >= PATTERN_LIST_END)
                        break;
                    /* Clear bit in the result. */
                    current_bits = result[rule_index >> 5];
                    current_bit = (1 << (rule_index & 0x1f));
                    if (current_bits & current_bit) {
                        result[rule_index >> 5] = current_bits - current_bit;
                        if (!--rule_count)
                            return MPM_NO_ERROR;
                    }
                }
            }
            if (rule_index == RULE_LIST_END)
                break;
            result_bits >>= 1;
        }

        pattern_list_next++;
        if (pattern_list_next >= pattern_list_last)
            goto mainloop;
    }

pcre_match:
#if PCRE_MAJOR >= 8 && PCRE_MINOR >= 32
    if (next_pattern->u2.pcre_extra && (((struct pcre_extra *)next_pattern->u2.pcre_extra)->flags & PCRE_EXTRA_EXECUTABLE_JIT))
        rule_index = pcre_jit_exec((const pcre *)next_pattern->u1.pcre, (pcre_extra *)next_pattern->u2.pcre_extra,
            (const char *)subject, (int)length, (int)offset, 0, ovector, 32, (pcre_jit_stack *)pcre_stack) >= 0;
    else
        rule_index = pcre_exec((const pcre *)next_pattern->u1.pcre, (pcre_extra *)next_pattern->u2.pcre_extra,
            (const char *)subject, (int)length, (int)offset, 0, ovector, 32) >= 0;
#else
    rule_index = pcre_exec((const pcre *)next_pattern->u1.pcre, (pcre_extra *)next_pattern->u2.pcre_extra,
        (const char *)subject, (int)length, (int)offset, 0, ovector, 32) >= 0;
#endif

    next_pattern++;
    if (rule_index)
        goto mainloop;

    rule_indices = next_pattern[-1].rule_indices;
    while (1) {
        rule_index = *rule_indices++;
        if (rule_index >= PATTERN_LIST_END)
            goto mainloop;
        /* Clear bit in the result. */
        current_bits = result[rule_index >> 5];
        current_bit = (1 << (rule_index & 0x1f));
        if (current_bits & current_bit) {
            result[rule_index >> 5] = current_bits - current_bit;
            if (!--rule_count)
                return MPM_NO_ERROR;
        }
    }
}

mpm_size mpm_private_compile_pcre(pattern_list_item *item)
{
    int options = 0;
    const char *errptr;
    int erroffset;

    if (item->u2.flags & MPM_ADD_CASELESS)
        options |= PCRE_CASELESS;
    if (item->u2.flags & MPM_ADD_MULTILINE)
        options |= PCRE_MULTILINE;
    if (item->u2.flags & MPM_ADD_ANCHORED)
        options |= PCRE_ANCHORED;
    if (item->u2.flags & MPM_ADD_DOTALL)
        options |= PCRE_DOTALL;
    if (item->u2.flags & MPM_ADD_EXTENDED)
        options |= PCRE_EXTENDED;

    item->u1.pcre = pcre_compile((const char *)item->u1.pcre, options, &errptr, &erroffset, NULL);
    item->u2.pcre_extra = NULL;
    if (!item->u1.pcre)
        return 1;

#if PCRE_MAJOR >= 8 && PCRE_MINOR >= 32
    item->u2.pcre_extra = pcre_study((const pcre *)item->u1.pcre, PCRE_STUDY_JIT_COMPILE, &errptr);
#else
    item->u2.pcre_extra = pcre_study((const pcre *)item->u1.pcre, 0, &errptr);
#endif
    return 0;
}

void mpm_private_free_pcre(pattern_list_item *item)
{
    if (item->u1.pcre)
        pcre_free(item->u1.pcre);
#if PCRE_MAJOR >= 8 && PCRE_MINOR >= 32
    if (item->u2.pcre_extra)
        pcre_free_study((pcre_extra *)item->u2.pcre_extra);
#else
    if (item->u2.pcre_extra)
        pcre_free(item->u2.pcre_extra);
#endif
}
