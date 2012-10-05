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

int mpm_exec(mpm_re *re, char *subject, int length, unsigned int *result)
{
    uint32_t current_character;
    uint8_t *state_map;
    int32_t next_offset;
    uint32_t current_result;
    uint32_t end_states;

    if (re->next_id != 0)
        return MPM_RE_IS_NOT_COMPILED;
    if (length == 0) {
        result[0] = 0;
        return MPM_NO_ERROR;
    }

    /* Simple matcher. */
    state_map = re->compiled_pattern + sizeof(uint32_t);
    current_result = 0;
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

    result[0] = current_result | GET_END_STATES(state_map);
    return MPM_NO_ERROR;
}

int mpm_exec4(mpm_re **re, char *subject, int length, unsigned int *result)
{
    uint32_t current_character;
    uint8_t *state_map0, *state_map1, *state_map2, *state_map3;
    int32_t next_offset0, next_offset1, next_offset2, next_offset3;
    uint32_t current_result0, current_result1, current_result2, current_result3;
    uint32_t end_states0, end_states1, end_states2, end_states3;

    if (re[0]->next_id != 0 || re[1]->next_id != 0 || re[2]->next_id != 0 || re[3]->next_id != 0)
        return MPM_RE_IS_NOT_COMPILED;

    if (length == 0) {
        result[0] = 0;
        result[1] = 0;
        result[2] = 0;
        result[3] = 0;
        return MPM_NO_ERROR;
    }

    /* Simple matcher. */
    state_map0 = re[0]->compiled_pattern;
    state_map1 = re[1]->compiled_pattern;
    state_map2 = re[2]->compiled_pattern;
    state_map3 = re[3]->compiled_pattern;
    current_result0 = 0;
    current_result1 = 0;
    current_result2 = 0;
    current_result3 = 0;
    do {
        /* The squence is optimized for performance. */
        current_character = *(uint8_t*)subject;
        next_offset0 = state_map0[current_character];
        next_offset1 = state_map1[current_character];
        next_offset2 = state_map2[current_character];
        next_offset3 = state_map3[current_character];
        end_states0 = GET_END_STATES(state_map0);
        end_states1 = GET_END_STATES(state_map1);
        end_states2 = GET_END_STATES(state_map2);
        end_states3 = GET_END_STATES(state_map3);
        next_offset0 = GET_NEXT_OFFSET(state_map0, 256, next_offset0);
        next_offset1 = GET_NEXT_OFFSET(state_map1, 256, next_offset1);
        next_offset2 = GET_NEXT_OFFSET(state_map2, 256, next_offset2);
        next_offset3 = GET_NEXT_OFFSET(state_map3, 256, next_offset3);
        subject++;
        current_result0 |= end_states0;
        current_result1 |= end_states1;
        current_result2 |= end_states2;
        current_result3 |= end_states3;
        state_map0 = NEXT_STATE_MAP(state_map0, next_offset0);
        state_map1 = NEXT_STATE_MAP(state_map1, next_offset1);
        state_map2 = NEXT_STATE_MAP(state_map2, next_offset2);
        state_map3 = NEXT_STATE_MAP(state_map3, next_offset3);
    } while (--length);

    result[0] = current_result0 | GET_END_STATES(state_map0);
    result[1] = current_result1 | GET_END_STATES(state_map1);
    result[2] = current_result2 | GET_END_STATES(state_map2);
    result[3] = current_result3 | GET_END_STATES(state_map3);
    return MPM_NO_ERROR;
}
