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
/*                        Calculate Levenshtein distance.                  */
/* ----------------------------------------------------------------------- */

int mpm_distance(mpm_re *re1, int index1, mpm_re *re2, int index2)
{
    mpm_re_pattern *pattern1;
    mpm_re_pattern *pattern2;
    uint32_t *word_code1, *word_code2;
    uint32_t i, j, size1, size2;
    int32_t a, b;
    int32_t *base, *other, *previous, *current;

    if (!(re1->flags & RE_MODE_COMPILE) || !(re2->flags & RE_MODE_COMPILE))
        return MPM_RE_ALREADY_COMPILED;

    pattern1 = re1->compile.patterns;
    while (pattern1 && index1 > 0) {
        pattern1 = pattern1->next;
        index1--;
    }
    if (!pattern1)
        return MPM_NO_SUCH_PATTERN;

    pattern2 = re2->compile.patterns;
    while (pattern2 && index2 > 0) {
        pattern2 = pattern2->next;
        index2--;
    }

    if (!pattern2)
        return MPM_NO_SUCH_PATTERN;

    /* We choose the smaller string as base to decrease memory consumption.  */
    if (pattern1->term_range_size <= pattern2->term_range_size) {
        word_code1 = pattern1->word_code;
        word_code2 = pattern2->word_code;
        size1 = pattern1->term_range_size + 1;
        size2 = pattern2->term_range_size + 1;
    } else {
        word_code1 = pattern2->word_code;
        word_code2 = pattern1->word_code;
        size1 = pattern2->term_range_size + 1;
        size2 = pattern1->term_range_size + 1;
    }

    base = (int32_t *)malloc(size1 * 2 * sizeof(int32_t));
    if (!base)
        return MPM_NO_MEMORY;

    for (i = 0; i < size1; i++)
        base[i] = i;

    other = base + size1;
    current = base;
    for (j = 1; j < size2; j++) {
        if (current == base) {
            previous = base;
            current = other;
        } else {
            previous = other;
            current = base;
        }
        current[0] = j;

        for (i = 1; i < size1; i++) {
            a = previous[i];
            b = current[i - 1];
            if (a > b)
                a = b;
            a++;
            b = previous[i - 1];
            if (a > b) {
                a = b + (memcmp(word_code1 + word_code1[i - 1], word_code2 + word_code2[j - 1], 32) != 0);
            }
            current[i] = a;
        }
    }

    a = current[size1 - 1];
    free(base);
    return -a;
}
