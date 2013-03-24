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

#define DISTANCE_TRESHOLD 20

static mpm_uint8 population_count[256] = {
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8,
};

/* ----------------------------------------------------------------------- */
/*                        Calculate Levenshtein distance.                  */
/* ----------------------------------------------------------------------- */

int mpm_distance(mpm_re *re1, mpm_size index1, mpm_re *re2, mpm_size index2)
{
    mpm_re_pattern *pattern1;
    mpm_re_pattern *pattern2;
    mpm_uint32 *word_code1, *word_code2;
    mpm_uint32 *word_code_compare1, *word_code_compare2;
    mpm_uint32 i, j, size1, size2, start1, start2;
    mpm_uint32 prefix_size;
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
        start1 = pattern1->term_range_start;
        start2 = pattern2->term_range_start;
    } else {
        word_code1 = pattern2->word_code;
        word_code2 = pattern1->word_code;
        size1 = pattern2->term_range_size + 1;
        size2 = pattern1->term_range_size + 1;
        start1 = pattern2->term_range_start;
        start2 = pattern1->term_range_start;
    }

    prefix_size = 0;
    for (i = 0; i < size1; ++i) {
        if (i > 0) {
            word_code_compare1 = word_code1 + word_code1[i - 1];
            word_code_compare2 = word_code2 + word_code2[i - 1];
            if (memcmp(word_code_compare1, word_code_compare2, (CHAR_SET_SIZE * sizeof(mpm_uint32))) != 0)
                break;
            word_code_compare1 += CHAR_SET_SIZE;
            word_code_compare2 += CHAR_SET_SIZE;
        } else {
            word_code_compare1 = word_code1 + size1 - 1;
            word_code_compare2 = word_code2 + size2 - 1;
        }

        if (*word_code_compare1 == DFA_NO_DATA) {
            if (*word_code_compare2 != DFA_NO_DATA)
                break;
        } else if (*word_code_compare2 == DFA_NO_DATA)
            break;

        while (1) {
            ++word_code_compare1;
            ++word_code_compare2;
            if (*word_code_compare1 == DFA_NO_DATA || *word_code_compare2 == DFA_NO_DATA)
                break;
            if (*word_code_compare1 - start1 != *word_code_compare2 - start2)
                break;
        }

        if (*word_code_compare1 != DFA_NO_DATA || *word_code_compare2 != DFA_NO_DATA)
            break;
        if (i != 0)
            prefix_size++;
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

    a = -(int32_t)current[size1 - 1] + (int32_t)(prefix_size / 3);
    free(base);
    return a < 0 ? a : -1;
}

/* ----------------------------------------------------------------------- */
/*                          Rating regular expressions.                    */
/* ----------------------------------------------------------------------- */

#define ONES_MAX_TRESHOLD 8

int mpm_private_rating(mpm_re_pattern *pattern)
{
    mpm_uint32 *word_code;
    mpm_uint8 *bit_set, *bit_set_end;
    mpm_uint32 i, size, ones;
    int rate, max, char_types[3];

    word_code = pattern->word_code;
    size = pattern->term_range_size;
    char_types[0] = 0;
    char_types[1] = 0;
    char_types[2] = 0;

    for (i = 0; i < size; ++i) {
        bit_set = (mpm_uint8 *)(word_code + word_code[i]);
        bit_set_end = bit_set + (CHAR_SET_SIZE * sizeof(mpm_uint32));
        ones = 0;
        while (bit_set < bit_set_end && ones <= ONES_MAX_TRESHOLD)
            ones += population_count[*bit_set++];

        if (ones > ONES_MAX_TRESHOLD)
            char_types[2]++;
        else if (ones > 4)
            char_types[1]++;
        else if (ones > 2)
            char_types[0]++;
    }
    /* Result between 0-16. */
    rate = ((char_types[2] * 8) + (char_types[1] * 2) + char_types[0]) * 2 / pattern->term_range_size;
    if (pattern->term_range_size >= 14)
        max = pattern->term_range_size / 4;
    else if (pattern->term_range_size >= 9)
        max = pattern->term_range_size / 3;
    else if (pattern->term_range_size >= 6)
        max = pattern->term_range_size / 2;
    else
        max = 2;

    if (char_types[2] + char_types[1] / 2 + char_types[0] / 4 >= max)
        rate = 16;
    if (pattern->term_range_size < 3)
        rate = rate / 2;
    if (pattern->term_range_size < 6)
        rate = rate * 3 / 4;

    /* Clamp result. */
    if (rate <= 0)
        rate = 1;
    return rate;
}

int mpm_rating(mpm_re *re, mpm_size index)
{
    mpm_re_pattern *pattern;
    if (!(re->flags & RE_MODE_COMPILE))
        return MPM_RE_ALREADY_COMPILED;

    pattern = re->compile.patterns;
    while (pattern && index > 0) {
        pattern = pattern->next;
        index--;
    }
    if (!pattern)
        return MPM_NO_SUCH_PATTERN;

    return -mpm_private_rating(pattern);
}

#undef ONES_MAX_TRESHOLD

/* ----------------------------------------------------------------------- */
/*                        Clustering regular expressions.                  */
/* ----------------------------------------------------------------------- */

#define DISTANCE(x, y) \
    distance_matrix[(items[x].group_id & 0xffff) + (items[y].group_id & 0xffff) * distance_matrix_size]

static int split_group(int *distance_matrix, mpm_size distance_matrix_size,
    mpm_cluster_item *items, mpm_size no_items, mpm_uint32 *next_index)
{
    mpm_size x, y;
    mpm_size left, right;
    int distance, max_distance, return_value;
    mpm_cluster_item item;
    mpm_uint32 group_id, other_group_id;
    mpm_re *re;

    if (no_items <= 1)
        return MPM_NO_ERROR;

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

    if (no_items <= 32 && max_distance < DISTANCE_TRESHOLD) {
        if (no_items <= 2)
            return MPM_NO_ERROR;

        re = NULL;
        for (x = 0; x < no_items; x++) {
            if ((return_value = mpm_combine(&re, items[x].re, MPM_COMBINE_COPY)) != MPM_NO_ERROR) {
                if (re)
                    mpm_free(re);
                return return_value;
            }
        }
        return_value = mpm_compile(re, 0);
        mpm_free(re);
        if (return_value != MPM_STATE_MACHINE_LIMIT)
            return MPM_NO_ERROR;
    }

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
        return MPM_NO_ERROR;

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
    if ((return_value = split_group(distance_matrix, distance_matrix_size, items, left, next_index)) != MPM_NO_ERROR)
        return return_value;
    return split_group(distance_matrix, distance_matrix_size, items + left, no_items - left + 1, next_index);
}

#undef DISTANCE_TRESHOLD
#undef DISTANCE

int mpm_clustering(mpm_cluster_item *items, mpm_size no_items, mpm_uint32 flags)
{
    mpm_size x, y;
    mpm_uint32 next_index, prev_group;
    int *distance_matrix;
    int *rate_vector;
    int distance, return_value;
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
        y = !(items[x].re->flags & RE_MODE_COMPILE);
        if (y || items[x].re->compile.next_id != 1) {
            free(distance_matrix);
            free(rate_vector);
            return y ? MPM_RE_ALREADY_COMPILED : MPM_INVALID_ARGS;
        }
        rate_vector[x] = mpm_private_rating(items[x].re->compile.patterns);
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
    if ((return_value = split_group(distance_matrix, no_items, items, no_items, &next_index))) {
        free(distance_matrix);
        return return_value;
    }

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
