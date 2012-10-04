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

#define MOVE_STATE_MAP(map, offset) \
    (mpm_state_map *)((char*)(map) + (offset))

int mpm_exec(mpm_re *re, char *subject, int length, unsigned int *result)
{
    mpm_state_map *state_map;
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
    state_map = (mpm_state_map *)re->compiled_pattern;
    current_result = 0;
    do {
        /* The squence is optimized for performance. */
        next_offset = state_map->map[(uint8_t)*subject];
        end_states = state_map->end_states;
        next_offset = state_map->offsets[next_offset];
        subject++;
        current_result |= end_states;
        state_map = MOVE_STATE_MAP(state_map, next_offset);
    } while (--length);

    result[0] = current_result | state_map->end_states;
    return MPM_NO_ERROR;
}

int mpm_exec4(mpm_re **re, char *subject, int length, unsigned int *result)
{
    mpm_state_map *state_map0, *state_map1, *state_map2, *state_map3;
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
    state_map0 = (mpm_state_map *)re[0]->compiled_pattern;
    state_map1 = (mpm_state_map *)re[1]->compiled_pattern;
    state_map2 = (mpm_state_map *)re[2]->compiled_pattern;
    state_map3 = (mpm_state_map *)re[3]->compiled_pattern;
    current_result0 = 0;
    current_result1 = 0;
    current_result2 = 0;
    current_result3 = 0;
    do {
        /* The squence is optimized for performance. */
        next_offset0 = state_map0->map[(uint8_t)*subject];
        next_offset1 = state_map1->map[(uint8_t)*subject];
        next_offset2 = state_map2->map[(uint8_t)*subject];
        next_offset3 = state_map3->map[(uint8_t)*subject];
        end_states0 = state_map0->end_states;
        end_states1 = state_map1->end_states;
        end_states2 = state_map2->end_states;
        end_states3 = state_map3->end_states;
        next_offset0 = state_map0->offsets[next_offset0];
        next_offset1 = state_map1->offsets[next_offset1];
        next_offset2 = state_map2->offsets[next_offset2];
        next_offset3 = state_map3->offsets[next_offset3];
        subject++;
        current_result0 |= end_states0;
        current_result1 |= end_states1;
        current_result2 |= end_states2;
        current_result3 |= end_states3;
        state_map0 = MOVE_STATE_MAP(state_map0, next_offset0);
        state_map1 = MOVE_STATE_MAP(state_map1, next_offset1);
        state_map2 = MOVE_STATE_MAP(state_map2, next_offset2);
        state_map3 = MOVE_STATE_MAP(state_map3, next_offset3);
    } while (--length);

    result[0] = current_result0 | state_map0->end_states;
    result[1] = current_result1 | state_map1->end_states;
    result[2] = current_result2 | state_map2->end_states;
    result[3] = current_result3 | state_map3->end_states;
    return MPM_NO_ERROR;
}
