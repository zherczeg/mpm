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

int mpm_exec(mpm_re *re, char *subject, int length, unsigned int *result)
{
    uint8_t* compiled_pattern;
    mpm_state_map *state_map;
    uint32_t next_offset, current_result, end_states;

    if (re->next_id != 0)
        return MPM_RE_IS_NOT_COMPILED;

    /* Simple matcher. */
    compiled_pattern = re->compiled_pattern;
    state_map = (mpm_state_map *)compiled_pattern;
    current_result = state_map->end_states;
    while (length > 0) {
        /* The squence is optimized for performance. */
        next_offset = state_map->map[(uint8_t)*subject];
        next_offset = state_map->offsets[next_offset];
        state_map = (mpm_state_map *)(compiled_pattern + next_offset);
        end_states = state_map->end_states;
        length--;
        subject++;
        current_result |= end_states;
    }

    result[0] = current_result;
    return MPM_NO_ERROR;
}
