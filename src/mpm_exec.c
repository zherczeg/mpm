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
    (((uint32_t*)(map))[-1])

#define GET_NEXT_OFFSET(map, offset, index) \
    (((int32_t*)((map) + (offset)))[index])

#define NEXT_STATE_MAP(map, offset) \
    ((map) + (offset))

int mpm_exec(mpm_re *re, char *subject, int length, int offset, unsigned int *result)
{
    uint32_t current_character;
    uint8_t *state_map;
    int32_t next_offset;
    uint32_t current_result;
    uint32_t end_states;

    if (re->flags & RE_MODE_COMPILE)
        return MPM_RE_IS_NOT_COMPILED;

    length -= offset;
    subject += offset;
    if (length == 0) {
        result[0] = 0;
        return MPM_NO_ERROR;
    }


    /* Simple matcher. */
    state_map = re->run.compiled_pattern + sizeof(uint32_t);
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
            current_character = *(uint8_t*)subject;
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
            current_character = *(uint8_t*)subject;
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
        current_character = *(uint8_t*)subject; \
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

int mpm_exec4(mpm_re **re, char *subject, int length, int offset, unsigned int *result)
{
    uint32_t current_character;
    uint8_t *state_map0, *state_map1, *state_map2, *state_map3;
    int32_t next_offset0, next_offset1, next_offset2, next_offset3;
    uint32_t current_result0, current_result1, current_result2, current_result3;
    uint32_t end_states0, end_states1, end_states2, end_states3;

    if ((re[0]->flags & RE_MODE_COMPILE) || (re[1]->flags & RE_MODE_COMPILE)
            || (re[2]->flags & RE_MODE_COMPILE) || (re[3]->flags & RE_MODE_COMPILE))
        return MPM_RE_IS_NOT_COMPILED;

    length -= offset;
    subject += offset;
    if (length == 0) {
        result[0] = 0;
        result[1] = 0;
        result[2] = 0;
        result[3] = 0;
        return MPM_NO_ERROR;
    }

    /* Simple matcher. */
    state_map0 = re[0]->run.compiled_pattern + sizeof(uint32_t);
    state_map1 = re[1]->run.compiled_pattern + sizeof(uint32_t);
    state_map2 = re[2]->run.compiled_pattern + sizeof(uint32_t);
    state_map3 = re[3]->run.compiled_pattern + sizeof(uint32_t);
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

    result[0] = current_result0 | GET_END_STATES(state_map0);
    result[1] = current_result1 | GET_END_STATES(state_map1);
    result[2] = current_result2 | GET_END_STATES(state_map2);
    result[3] = current_result3 | GET_END_STATES(state_map3);
    return MPM_NO_ERROR;
}
