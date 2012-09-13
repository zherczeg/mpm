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

int mpm_exec(mpm_re *re, char *subject, int length)
{
    uint8_t* compiled_pattern;
    mpm_offset_map *offset_map;
    uint32_t next_offset;

    if (re->next_id != 0)
        return 0;

    if (re->flags & ALL_END_STATES) {
        /* Simple matcher. */
        compiled_pattern = re->compiled_pattern;
        offset_map = (mpm_offset_map *)compiled_pattern;
        while (length > 0) {
            next_offset = offset_map->offsets[offset_map->map[(uint8_t)*subject]];
            if (next_offset == DFA_NO_DATA)
                return 1;
            offset_map = (mpm_offset_map *)(compiled_pattern + next_offset);
            length--;
            subject++;
        }
        return 0;
    }

    return 0;
}