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

int mpm_distance(mpm_re *re1, mpm_size index1, mpm_re *re2, mpm_size index2)
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
            if (a > b)
                a = b + (memcmp(word_code1 + word_code1[i - 1], word_code2 + word_code2[j - 1], 32) != 0);
            current[i] = a;
        }
    }

    a = current[size1 - 1];
    free(base);
    return -a;
}

/* ----------------------------------------------------------------------- */
/*                        Clustering regular expressions.                  */
/* ----------------------------------------------------------------------- */

#define ONES_MAX_TRESHOLD 8

static int mpm_rate(mpm_re *re, mpm_size index)
{
    mpm_re_pattern *pattern;
    uint32_t *word_code, *bit_set, *bit_set_end;
    uint32_t i, size, ones, value;
    int rate, char_types[3];

    if (!(re->flags & RE_MODE_COMPILE))
        return MPM_RE_ALREADY_COMPILED;

    pattern = re->compile.patterns;
    while (pattern && index > 0) {
        pattern = pattern->next;
        index--;
    }
    if (!pattern)
        return MPM_NO_SUCH_PATTERN;

    word_code = pattern->word_code;
    size = pattern->term_range_size;
    char_types[0] = 0;
    char_types[1] = 0;
    char_types[2] = 0;

    for (i = 0; i < size; ++i) {
        bit_set = word_code + word_code[i];
        bit_set_end = bit_set + CHAR_SET_SIZE;
        ones = 0;
        while (bit_set < bit_set_end && ones <= ONES_MAX_TRESHOLD) {
            value = *bit_set++;
            if (value) {
                if (value == 0xffffffff)
                    ones += 32;
                else {
                    while (value) {
                        if (value & 0x1)
                            ones++;
                        value >>= 1;
                    }
                }
            }
        }
        if (ones > ONES_MAX_TRESHOLD)
            char_types[2]++;
        else if (ones > 4)
            char_types[1]++;
        else if (ones > 2)
            char_types[0]++;
    }
    /* Result between 0-16. */
    rate = ((char_types[2] * 8) + (char_types[1] * 2) + char_types[0]) * 2 / pattern->term_range_size;
    if (char_types[2] + char_types[1] / 2 + char_types[0] / 8 > 6)
        rate = 16;
    if (pattern->term_range_size < 3)
        rate = rate / 2;
    if (pattern->term_range_size < 6)
        rate = rate * 3 / 4;

    /* Clamp result. */
    if (rate <= 0)
        rate = 1;
    return -rate;
}

#undef ONES_MAX_TRESHOLD

#define DISTANCE(x, y) \
    distance_matrix[(items[x].group_id & 0xffff) + (items[y].group_id & 0xffff) * distance_matrix_size]

static void split_group(int *distance_matrix, mpm_size distance_matrix_size,
    mpm_cluster_item *items, mpm_size no_items, mpm_uint32 *next_index)
{
    mpm_size x, y;
    mpm_size left, right;
    int distance, max_distance;
    mpm_cluster_item item;
    mpm_uint32 group_id, other_group_id;

    if (no_items <= 1)
        return;

    group_id = items[0].group_id & ~0xffff;
    *next_index += 0x10000;
    other_group_id = *next_index;

    max_distance = DISTANCE(1, 0);
    left = 0;
    right = 1;

    /* Search those two items, which distance is the highest. */
    for (y = 0; y < no_items; y++)
        for (x = y + 1; x < no_items; x++) {
            distance = DISTANCE(x, y);
            if (distance > max_distance) {
                max_distance = distance;
                left = y;
                right = x;
            }
        }

    if (no_items <= 32 && max_distance < 32)
        return;

    no_items--;
    if (left != 0) {
        item = items[left];
        items[left] = items[0];
        items[0] = item;
    }
    items[0].group_id = (items[0].group_id & 0xffff) | group_id;
    if (right != no_items) {
        item = items[right];
        items[right] = items[no_items];
        items[no_items] = item;
    }
    items[no_items].group_id = (items[no_items].group_id & 0xffff) | other_group_id;

    if (no_items <= 1)
        return;

    left = 1;
    right = no_items - 1;
    while (left < right) {
        if (DISTANCE(0, left) <= DISTANCE(left, no_items)) {
            items[left].group_id = (items[left].group_id & 0xffff) | group_id;
            left++;
        } else {
            item = items[right];
            items[right] = items[left];
            items[left] = item;
            items[right].group_id = (items[right].group_id & 0xffff) | other_group_id;
            right--;
        }
    }

    if (DISTANCE(0, left) <= DISTANCE(left, no_items)) {
        items[left].group_id = (items[left].group_id & 0xffff) | group_id;
        left++;
    } else
        items[left].group_id = (items[left].group_id & 0xffff) | other_group_id;

    /* printf("Divide: %d Left: %d Right: %d\n", (int)no_items + 1, (int)left, (int)(no_items - left + 1)); */

    /* Recursive implementation. */
    split_group(distance_matrix, distance_matrix_size, items, left, next_index);
    split_group(distance_matrix, distance_matrix_size, items + left, no_items - left + 1, next_index);
}

#undef DISTANCE

int mpm_clustering(mpm_cluster_item *items, mpm_size no_items, mpm_uint32 flags)
{
    mpm_size x, y;
    mpm_uint32 next_index, prev_group;
    int *distance_matrix;
    int *rate_vector;
    int distance, rate;
#if defined MPM_VERBOSE && MPM_VERBOSE
    mpm_size count = 0, max = 0;
#endif

    if (!items || no_items <= 0 || no_items > 65535)
        return MPM_INVALID_ARGS;

    rate_vector = (int *)malloc(no_items * sizeof(int));
    if (!rate_vector)
        return MPM_NO_MEMORY;

    distance_matrix = (int *)malloc(no_items * no_items * sizeof(int));
    if (!distance_matrix) {
        free(rate_vector);
        return MPM_NO_MEMORY;
    }

#if defined MPM_VERBOSE && MPM_VERBOSE
    if (flags & MPM_CLUSTERING_VERBOSE)
        printf("Rating patterns\n");
#endif

    for (x = 0; x < no_items; x++) {
        rate = mpm_rate(items[x].re, 0);
        if (rate > 0) {
            free(distance_matrix);
            free(rate_vector);
            return rate;
        }
        rate_vector[x] = -rate;
    }

#if defined MPM_VERBOSE && MPM_VERBOSE
    if (flags & MPM_CLUSTERING_VERBOSE) {
        max = ((no_items * (no_items - 1)) / 2) >> 10;
        printf("Generate distance matrix: 0%%");
        fflush(stdout);
    }
#endif

    for (y = 0; y < no_items; y++) {
        items[y].group_id = y;
        for (x = 0; x < no_items; x++) {
             if (y < x) {
                 distance = mpm_distance(items[x].re, 0, items[y].re, 0);
                 if (distance > 0) {
                     free(distance_matrix);
                     free(rate_vector);
                     return distance;
                 }
                 distance_matrix[y * no_items + x] = (-distance) * rate_vector[x] * rate_vector[y];
#if defined MPM_VERBOSE && MPM_VERBOSE
                 if (flags & MPM_CLUSTERING_VERBOSE) {
                     count++;
                     if (!(count & 0x3ff)) {
                         printf("\rGenerate distance matrix: %d%%", (int)((count >> 10) * 100 / max));
                         fflush(stdout);
                     }
                 }
#endif
             } else if (y > x)
                 distance_matrix[y * no_items + x] = distance_matrix[x * no_items + y];
             else
                 distance_matrix[y * no_items + x] = 0;
        }
    }

    free(rate_vector);

#if defined MPM_VERBOSE && MPM_VERBOSE
    if (flags & MPM_CLUSTERING_VERBOSE)
        printf("\rGenerate distance matrix: 100%%\nCreating groups\n");
#endif

    next_index = 0;
    split_group(distance_matrix, no_items, items, no_items, &next_index);

    next_index = 0;
    prev_group = items[0].group_id & ~0xffff;
    while (no_items--) {
        if ((items[0].group_id & ~0xffff) != prev_group) {
            prev_group = items[0].group_id & ~0xffff;
            items[0].group_id = ++next_index;
        } else
            items[0].group_id = next_index;
        items++;
    }

#if defined MPM_VERBOSE && MPM_VERBOSE
    if (flags & MPM_CLUSTERING_VERBOSE)
        printf("Clustering is done\n");
#endif

    free(distance_matrix);
    return MPM_NO_ERROR;
}
