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
#include "mpm_pcre_internal.h"
#include <math.h>

/* ----------------------------------------------------------------------- */
/*                          Defines and structures.                        */
/* ----------------------------------------------------------------------- */

#define ARENA_FRAGMENT_SIZE (16384 - sizeof(void*))
#define MINIMUM_BYTE_CODES 3

typedef struct rule_index_list {
    struct rule_index_list *next;
    mpm_uint32 rule_index;
} rule_index_list;

typedef struct re_list {
    struct re_list *next;
    mpm_re *re;
    union {
        rule_index_list *rule_indices;
        mpm_uint32 *rule_indices_ptr;
    } u;
} re_list;

typedef struct sub_pattern_list {
    struct sub_pattern_list *next;
    rule_index_list *rule_indices;
    struct sub_pattern_list *left_child;
    struct sub_pattern_list *right_child;
    mpm_byte_code *byte_code;
    mpm_char8 *from;
    union {
        struct {
            struct sub_pattern_list *hash_next;
            mpm_uint32 hash;
            mpm_uint32 last_rule_index;
        } s1;
        struct {
            float strength;
            float priority;
            mpm_uint32 distance;
        } s2;
    } u;
    mpm_uint32 length;
} sub_pattern_list;

typedef struct mpm_arena_fragment {
    struct mpm_arena_fragment *next;
    mpm_uint8 data[ARENA_FRAGMENT_SIZE];
} mpm_arena_fragment;

typedef struct mpm_arena {
    mpm_arena_fragment *first;
    mpm_arena_fragment *last;
    mpm_size consumed_size;

    /* Other members. */
    mpm_compile_rules_args args;
    sub_pattern_list **map;
    sub_pattern_list *first_pattern;
    re_list *first_re;
    mpm_uint32 mask;
    mpm_uint32 pattern_count;
    mpm_uint32 re_count;
    mpm_uint32 rule_index;
} mpm_arena;

/* ----------------------------------------------------------------------- */
/*                                   Arena.                                */
/* ----------------------------------------------------------------------- */

static void * arena_malloc(mpm_arena *arena, mpm_size size)
{
    void *data;
    mpm_arena_fragment *new_fragment;

    /* Should never happen. */
    if (size >= ARENA_FRAGMENT_SIZE)
        return NULL;

    if (arena->consumed_size + size <= ARENA_FRAGMENT_SIZE) {
        data = arena->last->data + arena->consumed_size;
        arena->consumed_size += size;
        return data;
    }

    new_fragment = (mpm_arena_fragment *)malloc(sizeof(mpm_arena_fragment));
    if (!new_fragment)
        return NULL;

    arena->last->next = new_fragment;
    arena->last = new_fragment;
    new_fragment->next = NULL;
    arena->consumed_size = size;
    return new_fragment->data;
}

static void free_arena(mpm_arena *arena)
{
    mpm_arena_fragment *current = arena->first;
    mpm_arena_fragment *next;
    re_list *re = arena->first_re;

    while (re) {
        mpm_free(re->re);
        re = re->next;
    }
    while (current) {
        next = current->next;
        free(current);
        current = next;
    }
    if (arena->map)
        free(arena->map);
}

/* ----------------------------------------------------------------------- */
/*                               Hash table.                               */
/* ----------------------------------------------------------------------- */

static mpm_uint32 compute_hash(mpm_uint8 *data_ptr, mpm_size size)
{
    mpm_uint32 hash = 0xaaaaaaaa;

    /* Hash from Arash Partow. */
    while (size > 1) {
        // Processing two bytes in one step.
        hash ^= (hash << 7) ^ ((*data_ptr) * (hash >> 3));
        data_ptr++;
        hash ^= ~((hash << 11) + ((*data_ptr) ^ (hash >> 5)));
        data_ptr++;
        size -= 2;
    }
    if (size > 0)
        hash ^= (hash << 7) ^ ((*data_ptr) * (hash >> 3));
    return hash;
}

static int realloc_hash_table(mpm_arena *arena)
{
    sub_pattern_list **new_map;
    sub_pattern_list *sub_pattern;
    mpm_uint32 mask = arena->mask;
    mpm_size size = (mask + 1) * sizeof(sub_pattern_list *);

    free(arena->map);
    arena->map = (sub_pattern_list **)malloc(size);
    new_map = arena->map;
    if (!new_map)
        return MPM_NO_MEMORY;

    memset(new_map, 0, size);
    sub_pattern = arena->first_pattern;
    do {
        sub_pattern->u.s1.hash_next = new_map[sub_pattern->u.s1.hash & mask];
        new_map[sub_pattern->u.s1.hash & mask] = sub_pattern;
        sub_pattern = sub_pattern->next;
    } while (sub_pattern);

    return MPM_NO_ERROR;
}

/* ----------------------------------------------------------------------- */
/*                      Sub-pattern build functions.                       */
/* ----------------------------------------------------------------------- */

static int mpm_private_get_byte_code(mpm_byte_code **byte_code, mpm_char8 *pattern, mpm_uint32 flags);

static int compile_pattern(mpm_byte_code **byte_code, mpm_rule_pattern *rule)
{
    mpm_re *re = mpm_create();
    mpm_uint32 flags = (rule->flags & ~MPM_RULE_NEW);
    int error_code;

    if (GET_FIXED_SIZE(flags) > 0)
        flags |= MPM_ADD_CASELESS;

    if (!re)
        return MPM_NO_MEMORY;

    error_code = mpm_private_add(re, rule->pattern, 0, flags | MPM_ADD_TEST_RATING);
    mpm_free(re);

    if (error_code != MPM_NO_ERROR)
        return error_code;

    return mpm_private_get_byte_code(byte_code, rule->pattern, flags);
}

static int recursive_mark(mpm_arena *arena, sub_pattern_list *sub_pattern)
{
    int error_code;
    rule_index_list *index;
    struct sub_pattern_list *child;

    index = (rule_index_list *)arena_malloc(arena, sizeof(rule_index_list));
    if (!index)
        return MPM_NO_MEMORY;
    index->next = sub_pattern->rule_indices;
    sub_pattern->rule_indices = index;
    index->rule_index = arena->rule_index;
    sub_pattern->u.s1.last_rule_index = arena->rule_index;

    /* Mark children. */
    child = sub_pattern->left_child;
    if (child && child->u.s1.last_rule_index != arena->rule_index) {
        error_code = recursive_mark(arena, child);
        if (error_code != MPM_NO_ERROR)
            return error_code;
    }

    child = sub_pattern->right_child;
    if (child && child->u.s1.last_rule_index != arena->rule_index)
        return recursive_mark(arena, child);
    return MPM_NO_ERROR;
}

static void print_pattern(sub_pattern_list *sub_pattern);

static int process_pattern(mpm_arena *arena, mpm_byte_code *byte_code, mpm_uint32 from, mpm_uint32 to, sub_pattern_list **parent)
{
    int error_code;
    mpm_char8 *byte_code_from;
    sub_pattern_list *sub_pattern;
    mpm_uint32 offset, byte_code_length;
    mpm_uint32 left_offset, right_offset;
    mpm_uint32 count1, count2, increase;
    mpm_uint32 hash;

    if (from >= to)
        return MPM_INTERNAL_ERROR;

    byte_code_length = byte_code->byte_code_data[from].byte_code_length;
    if (from + byte_code_length == to) {
        /* Likely a bracketed expression. Trim brackets. */
        offset = from + 1;
        while (1) {
            if (offset >= to)
                break;
            if (byte_code->byte_code_data[offset].byte_code_length) {
                from = offset;
                while (1) {
                    /* This case should never happen. */
                    if (offset >= to)
                        return MPM_NO_ERROR;
                    if (!byte_code->byte_code_data[offset].byte_code_length)
                        break;
                    offset = offset + byte_code->byte_code_data[offset].byte_code_length;
                }
                to = offset;
                break;
            }
            offset++;
        }
    }

    byte_code_from = byte_code->byte_code + from;
    byte_code_length = to - from;
    hash = compute_hash(byte_code_from, byte_code_length);
    sub_pattern = arena->map[hash & arena->mask];
    while (sub_pattern) {
        if (sub_pattern->u.s1.hash == hash && sub_pattern->length == byte_code_length
                && memcmp(sub_pattern->from, byte_code_from, byte_code_length) == 0) {
            if (parent)
                *parent = sub_pattern;
            if (sub_pattern->u.s1.last_rule_index == arena->rule_index)
                return MPM_NO_ERROR;
            return recursive_mark(arena, sub_pattern);
        }
        sub_pattern = sub_pattern->u.s1.hash_next;
    }

    sub_pattern = (sub_pattern_list *)arena_malloc(arena, sizeof(sub_pattern_list));
    if (!sub_pattern)
        return MPM_NO_MEMORY;
    sub_pattern->left_child = NULL;
    sub_pattern->right_child = NULL;
    sub_pattern->u.s1.hash = hash;
    sub_pattern->from = byte_code_from;
    sub_pattern->byte_code = byte_code;
    sub_pattern->length = byte_code_length;
    sub_pattern->u.s1.last_rule_index = arena->rule_index;

    if (parent)
        *parent = sub_pattern;

    /* Append this rule index. */
    sub_pattern->rule_indices = (rule_index_list *)arena_malloc(arena, sizeof(rule_index_list));
    if (!sub_pattern->rule_indices)
        return MPM_NO_MEMORY;
    sub_pattern->rule_indices->next = NULL;
    sub_pattern->rule_indices->rule_index = arena->rule_index;

    /* Update arena. */
    hash &= arena->mask;
    sub_pattern->u.s1.hash_next = arena->map[hash];
    arena->map[hash] = sub_pattern;
    sub_pattern->next = arena->first_pattern;
    arena->first_pattern = sub_pattern;
    arena->pattern_count++;

    left_offset = from + byte_code->byte_code_data[from].byte_code_length;
    right_offset = from;
    while (1) {
        byte_code_length = byte_code->byte_code_data[right_offset].byte_code_length;
        if (right_offset + byte_code_length >= to)
            break;
        right_offset += byte_code_length;
    }

    offset = from;
    count1 = 0;
    count2 = 0;
    while (offset < to) {
        if (byte_code->byte_code_data[offset].byte_code_length) {
            increase = 1;
            if (byte_code->byte_code_data[offset].pattern_length & BYTE_CODE_IS_BRACKET)
                increase = MINIMUM_BYTE_CODES;
            if (byte_code->byte_code_data[offset].pattern_length & BYTE_CODE_HAS_LOW_VALUE)
                increase = 0;
            if (offset >= left_offset)
                count1 += increase;
            if (offset < right_offset)
                count2 += increase;
        }
        offset++;
    }

    if (count1 >= MINIMUM_BYTE_CODES) {
        error_code = process_pattern(arena, byte_code, left_offset, to, &sub_pattern->left_child);
        if (error_code != MPM_NO_ERROR)
            return error_code;
    }

    if (count2 >= MINIMUM_BYTE_CODES)
        return process_pattern(arena, byte_code, from, right_offset, &sub_pattern->right_child);

    return MPM_NO_ERROR;
}

/* ----------------------------------------------------------------------- */
/*                     Sub-pattern search functions.                       */
/* ----------------------------------------------------------------------- */

static void compute_strength(mpm_arena *arena, float *rule_strength)
{
    sub_pattern_list *sub_pattern = arena->first_pattern;
    rule_index_list *index;
    float sum;

    do {
        sum = 0.0;
        index = sub_pattern->rule_indices;
        do {
            sum += rule_strength[index->rule_index];
            index = index->next;
        } while (index);
        sub_pattern->u.s2.priority = sum * sub_pattern->u.s2.strength
            * (sqrt(sub_pattern->length) * arena->args.length_scale);
        sub_pattern = sub_pattern->next;
    } while (sub_pattern);
}

static mpm_uint32 recursive_outer_distance(mpm_arena *arena, sub_pattern_list *sub_pattern)
{
    mpm_uint32 value, left_child = (0 << 1), right_child = (0 << 1);
    float coefficient;

    if (sub_pattern->u.s2.distance & 0x1)
        return sub_pattern->u.s2.distance & ~0x1;

    if (sub_pattern->left_child)
        left_child = recursive_outer_distance(arena, sub_pattern->left_child);

    if (sub_pattern->right_child)
        right_child = recursive_outer_distance(arena, sub_pattern->right_child);

    if (left_child == (0 << 1) && right_child == (0 << 1))
        value = (0 << 1);
    else if (left_child == (0 << 1) || (left_child > right_child && right_child != (0 << 1)))
        value = right_child + (1 << 1);
    else
        value = left_child + (1 << 1);

    if (value > (0 << 1)) {
        coefficient = sqrt((float)(value >> 1)) * arena->args.outer_distance_scale;
        if (coefficient > 1.0)
            coefficient = 1.0;
        sub_pattern->u.s2.strength *= coefficient;
    }

    sub_pattern->u.s2.distance = value | 0x1;
    return value;
}

static void recursive_inner_distance(mpm_arena *arena, sub_pattern_list *sub_pattern)
{
    sub_pattern->u.s2.strength *= arena->args.inner_distance_scale;

    if (sub_pattern->left_child)
        recursive_inner_distance(arena, sub_pattern->left_child);
    if (sub_pattern->right_child)
        recursive_inner_distance(arena, sub_pattern->right_child);
}

static mpm_uint32 compute_new_cover(rule_index_list *rule_index, float *rule_strength)
{
    mpm_uint32 new_cover = 0;

    do {
        if (rule_strength[rule_index->rule_index] == 1.0)
            new_cover++;
        rule_index = rule_index->next;
    } while (rule_index);
    return new_cover;
}

static mpm_uint32 update_strengths(mpm_arena *arena, sub_pattern_list *sub_pattern, float *rule_strength)
{
    sub_pattern_list *current = arena->first_pattern;
    rule_index_list *rule_index = sub_pattern->rule_indices;
    mpm_uint32 total_cover = 0;

    do {
        total_cover++;
        rule_strength[rule_index->rule_index] *= arena->args.rule_strength_scale;
        rule_index = rule_index->next;
    } while (rule_index);

    sub_pattern->u.s2.distance = (1 << 1) | 1;
    sub_pattern->u.s2.strength = 0.0;

    do {
        recursive_outer_distance(arena, current);
        current = current->next;
    } while (current);

    recursive_inner_distance(arena, sub_pattern);
    return total_cover;
}

static int try_compile(mpm_arena *arena, sub_pattern_list *pattern)
{
    mpm_re *re = mpm_create();
    re_list *re_ptr;
    int error_code;

    if (!re)
        return MPM_NO_MEMORY;

    error_code = mpm_private_add(re, pattern->from, pattern->length, MPM_ADD_TEST_RATING);
    if (error_code != MPM_NO_ERROR) {
        mpm_free(re);
        return error_code;
    }

    re_ptr = (re_list *)arena_malloc(arena, sizeof(re_list));
    if (!re_ptr) {
        mpm_free(re);
        return MPM_NO_MEMORY;
    }

    re_ptr->next = arena->first_re;
    arena->first_re = re_ptr;
    re_ptr->re = re;
    re_ptr->u.rule_indices = pattern->rule_indices;
    arena->re_count ++;
    return MPM_NO_ERROR;
}

/* ----------------------------------------------------------------------- */
/*                       Rule list creation functions.                     */
/* ----------------------------------------------------------------------- */

static mpm_uint32 * compute_rule_list(re_list *first_re, mpm_uint32 rule_count, mpm_size *consumed_memory)
{
    mpm_uint32 *rule_indices;
    mpm_uint32 *rule_index;
    mpm_uint32 *touched_rules;
    mpm_uint32 *touched_rule_end;
    mpm_uint32 *touched_rule_ptr;
    re_list *re;
    rule_index_list *rule_ptr;
    mpm_size touched_rule_size;
    mpm_size rule_list_size;

    /* Calculating rule list size. */
    touched_rule_size = ((rule_count + 0x1f) & ~0x1f) >> 3;
    touched_rules = (mpm_uint32 *)malloc(touched_rule_size);
    if (!touched_rules)
        return NULL;
    touched_rule_end = touched_rules + (touched_rule_size >> 2);

    rule_list_size = 0;
    re = first_re;
    do {
        rule_ptr = re->u.rule_indices;

        memset(touched_rules, 0, touched_rule_size);
        do {
            touched_rules[rule_ptr->rule_index >> 5] |= 1 << (rule_ptr->rule_index & 0x1f);
            rule_ptr = rule_ptr->next;
        } while (rule_ptr);

        for (touched_rule_ptr = touched_rules; touched_rule_ptr < touched_rule_end; touched_rule_ptr++)
            if (*touched_rule_ptr)
                rule_list_size += 2 * sizeof(mpm_uint32);
        re = re->next;
    } while (re);

    if (consumed_memory)
        *consumed_memory = sizeof(mpm_rule_list) + rule_list_size;

    rule_indices = (mpm_uint32 *)malloc(rule_list_size);
    if (!rule_indices) {
        free(touched_rules);
        return NULL;
    }

    rule_index = rule_indices;
    re = first_re;
    do {
        rule_ptr = re->u.rule_indices;

        memset(touched_rules, 0, touched_rule_size);
        do {
            touched_rules[rule_ptr->rule_index >> 5] |= 1 << (rule_ptr->rule_index & 0x1f);
            rule_ptr = rule_ptr->next;
        } while (rule_ptr);

        re->u.rule_indices_ptr = rule_index;

        for (touched_rule_ptr = touched_rules; touched_rule_ptr < touched_rule_end; touched_rule_ptr++)
            if (*touched_rule_ptr) {
                *rule_index++ = (touched_rule_ptr - touched_rules) << 2;
                *rule_index++ = ~(*touched_rule_ptr);
            }
        re = re->next;
        rule_index[-2] |= re ? PATTERN_LIST_END : RULE_LIST_END;
    } while (re);

    free(touched_rules);
    return rule_indices;
}

static mpm_cluster_item * create_items(re_list *re, mpm_uint32 re_count)
{
    mpm_cluster_item *items;
    mpm_cluster_item *item;

    items = (mpm_cluster_item *)malloc(sizeof(mpm_cluster_item) * re_count);
    if (!items)
        return NULL;

    item = items;
    do {
        item->re = re->re;
        item->data = re->u.rule_indices_ptr;
        item++;
        re = re->next;
    } while (--re_count);

    return items;
}

static int final_phase(mpm_rule_list **result_rule_list, mpm_cluster_item *items, mpm_uint32 re_count, mpm_size *consumed_memory, mpm_uint32 flags)
{
    mpm_rule_list *rule_list;
    pattern_list_item *pattern_list;
    mpm_size last_consumed_memory;
    mpm_uint32 mapped_flags;
    mpm_uint32 pattern_list_length;
    mpm_uint32 group_id;
    mpm_re **re;
    mpm_uint32 i;
    int error_code;

    mapped_flags = 0;
    if (flags & MPM_COMPILE_RULES_VERBOSE)
        mapped_flags |= MPM_CLUSTERING_VERBOSE;

    error_code = mpm_clustering(items, re_count, mapped_flags);
    if (error_code != MPM_NO_ERROR)
        goto leave;

    mapped_flags = 0;
    if (flags & MPM_COMPILE_RULES_VERBOSE_STATS)
        mapped_flags |= MPM_COMPILE_VERBOSE_STATS;

    re = &items[0].re;
    group_id = items[0].group_id;
    pattern_list_length = 1;
    for (i = 1; i < re_count; i++) {
        if (items[i].group_id != group_id) {
            error_code = mpm_compile(*re, &last_consumed_memory, mapped_flags);
            if (error_code != MPM_NO_ERROR)
                goto leave;
            if (consumed_memory)
                *consumed_memory += last_consumed_memory;
            re = &items[i].re;
            group_id = items[i].group_id;
            pattern_list_length++;
        } else {
            error_code = mpm_combine(re, items[i].re, 0);
            if (error_code != MPM_NO_ERROR)
                goto leave;
            items[i].re = NULL;
        }
    }

    error_code = mpm_compile(*re, &last_consumed_memory, mapped_flags);
    if (error_code != MPM_NO_ERROR)
        goto leave;
    if (consumed_memory)
        *consumed_memory += last_consumed_memory;

    error_code = MPM_NO_MEMORY;
    rule_list = (mpm_rule_list *)malloc(sizeof(mpm_rule_list) + ((pattern_list_length - 1) * sizeof(pattern_list_item)));
    if (!rule_list)
        goto leave;

    rule_list->pattern_list_length = pattern_list_length;
    pattern_list = rule_list->pattern_list;
    for (i = 0; i < re_count; i++)
        if (items[i].re) {
            pattern_list->rule_indices = (mpm_uint32 *)items[i].data;
            pattern_list->re = items[i].re;
            pattern_list++;
        }

    *result_rule_list = rule_list;
    free(items);
    return MPM_NO_ERROR;

leave:
    for (i = 0; i < re_count; i++) {
        if (items[i].re)
            mpm_free(items[i].re);
    }

    free(items);
    return error_code;
}

/* ----------------------------------------------------------------------- */
/*                             Verbose functions.                          */
/* ----------------------------------------------------------------------- */

#if defined MPM_VERBOSE && MPM_VERBOSE
static void print_pattern(sub_pattern_list *sub_pattern)
{
    mpm_uint32 offset = sub_pattern->from - sub_pattern->byte_code->byte_code;
    mpm_uint32 end = offset + sub_pattern->length;
    char *pattern = (char*)sub_pattern->byte_code->pattern;
    mpm_byte_code_data *byte_code_data = sub_pattern->byte_code->byte_code_data;

    printf("/");
    while (offset < end) {
        printf("%.*s", byte_code_data[offset].pattern_length >> 4, pattern + byte_code_data[offset].pattern_offset);
        offset += byte_code_data[offset].byte_code_length;
    }
    printf("/\n");
}

static void print_arena_stats(mpm_arena *arena)
{
    mpm_arena_fragment *current = arena->first;
    mpm_size consumption = 0;

    while (current) {
        consumption += ARENA_FRAGMENT_SIZE;
        current = current->next;
    }
    printf("Total arena memory consumption: %ld\n", (long int)consumption);
}
#endif

/* ----------------------------------------------------------------------- */
/*                                 Main function.                          */
/* ----------------------------------------------------------------------- */

int mpm_compile_rules(mpm_rule_pattern *rules, mpm_size no_rule_patterns, mpm_rule_list **result_rule_list,
    mpm_size *consumed_memory, mpm_compile_rules_args *args, mpm_uint32 flags)
{
    mpm_byte_code **byte_codes;
    mpm_byte_code **byte_code;
    mpm_byte_code **byte_code_end;
    sub_pattern_list *pattern;
    sub_pattern_list *max;
    mpm_uint32 *rule_list;
    mpm_cluster_item *items;
    mpm_uint32 rule_count, i;
    mpm_uint32 new_cover, total_cover, all_cover;
    float *rule_strength;
    float max_priority;
    int error_code = MPM_NO_MEMORY;
    mpm_arena arena;

    *result_rule_list = NULL;
    if (consumed_memory)
        *consumed_memory = 0;
    if (!no_rule_patterns || !result_rule_list)
        return MPM_INVALID_ARGS;

    if (args) {
        arena.args = *args;
    } else {
        arena.args.no_selected_patterns = 0;
        arena.args.minimum_no_new_cover = 0;
        arena.args.rule_strength_scale = -1.0;
        arena.args.inner_distance_scale = -1.0;
        arena.args.outer_distance_scale = -1.0;
        arena.args.length_scale = -1.0;
    }

    if (arena.args.no_selected_patterns < 1) {
        if (no_rule_patterns < 16)
           arena.args.no_selected_patterns = 2;
        else if (no_rule_patterns < 64)
           arena.args.no_selected_patterns = 4;
        else if (no_rule_patterns < 512)
           arena.args.no_selected_patterns = 8;
        else if (no_rule_patterns < 4096)
           arena.args.no_selected_patterns = 16;
        else
           arena.args.no_selected_patterns = 32;
    }

    if (arena.args.rule_strength_scale < 0.0)
        arena.args.rule_strength_scale = 0.25;
    if (arena.args.rule_strength_scale > 1.0)
        arena.args.rule_strength_scale = 1.0;
    if (arena.args.inner_distance_scale < 0.0)
        arena.args.inner_distance_scale = 0.25;
    if (arena.args.inner_distance_scale > 1.0)
        arena.args.inner_distance_scale = 1.0;
    if (arena.args.outer_distance_scale < 0.0)
        arena.args.outer_distance_scale = 0.5;
    if (arena.args.length_scale < 0.0)
        arena.args.length_scale = 1.0;

    byte_codes = (mpm_byte_code **)malloc(no_rule_patterns * sizeof(mpm_byte_code *));
    if (!byte_codes)
        return MPM_NO_MEMORY;
    byte_code_end = byte_codes + no_rule_patterns;
    memset(byte_codes, 0, no_rule_patterns * sizeof(mpm_byte_code *));

    /* Arena initialization. */
    rule_strength = NULL;
    rule_list = NULL;
    arena.map = NULL;
    arena.first_pattern = NULL;
    arena.first_re = NULL;

    arena.first = (mpm_arena_fragment *)malloc(sizeof(mpm_arena_fragment));
    if (!arena.first)
        goto leave;
    arena.last = arena.first;
    arena.first->next = NULL;
    arena.consumed_size = 0;

    arena.mask = 64;
    while (arena.mask < no_rule_patterns * 4)
        arena.mask <<= 1;
    i = arena.mask * sizeof(sub_pattern_list *);
    arena.map = (sub_pattern_list **)malloc(i);
    if (!arena.map)
        goto leave;
    memset(arena.map, 0, i);
    arena.mask--;

    arena.pattern_count = 0;
    arena.re_count = 0;
    rule_count = 0;

    byte_code = byte_codes;
    do {
        if ((rule_count == 0) || (rules->flags & MPM_RULE_NEW)) {
            arena.rule_index = rule_count;
            rule_count++;
        }

        if ((flags & MPM_COMPILE_RULES_IGNORE_FIXED) && (GET_FIXED_SIZE(rules->flags)))
            error_code = MPM_UNSUPPORTED_PATTERN;
        else if ((flags & MPM_COMPILE_RULES_IGNORE_REGEX) && (!GET_FIXED_SIZE(rules->flags)))
            error_code = MPM_UNSUPPORTED_PATTERN;
        else
            error_code = compile_pattern(byte_code, rules);

        switch (error_code) {
        case MPM_NO_ERROR:
            error_code = process_pattern(&arena, *byte_code, 0, (*byte_code)->byte_code_length, NULL);
            if (error_code != MPM_NO_ERROR)
                goto leave;
            break;

        case MPM_TOO_LOW_RATING:
        case MPM_UNSUPPORTED_PATTERN:
            /* Ignore these patterns. */
            break;

        default:
            goto leave;
        }

        if ((arena.pattern_count << 1) >= arena.mask) {
            arena.mask = (arena.mask << 1) | 0x1;
            error_code = realloc_hash_table(&arena);
            if (error_code != MPM_NO_ERROR)
                goto leave;
        }
        byte_code++;
        rules++;
    } while (byte_code < byte_code_end);

    error_code = MPM_NO_MEMORY;
    free(arena.map);
    arena.map = NULL;

    if (!arena.pattern_count) {
        error_code = MPM_EMPTY_PATTERN;
        goto leave;
    }

    rule_strength = (float *)malloc(rule_count * sizeof(float));
    if (!rule_strength)
        goto leave;

    for (i = 0; i < rule_count; i++)
        rule_strength[i] = 1.0;

    pattern = arena.first_pattern;
    do {
        pattern->u.s2.strength = 1.0;
        pattern = pattern->next;
    } while (pattern);

    i = arena.args.no_selected_patterns;
    all_cover = 0;
    do {
        compute_strength(&arena, rule_strength);

        pattern = arena.first_pattern;
        max = pattern;
        max_priority = pattern->u.s2.priority;
        pattern->u.s2.distance = 0;
        pattern = pattern->next;

        while (pattern) {
            if (pattern->u.s2.priority > max_priority) {
                max = pattern;
                max_priority = pattern->u.s2.priority;
            }
            pattern->u.s2.distance = 0;
            pattern = pattern->next;
        }

        if (max_priority == 0.0)
            break;

        new_cover = compute_new_cover(max->rule_indices, rule_strength);
        if (new_cover < arena.args.minimum_no_new_cover) {
            max->u.s2.strength = 0.0;
            continue;
        }
        all_cover += new_cover;

        error_code = try_compile(&arena, max);
        max->u.s2.strength = 0.0;
        if (error_code == MPM_TOO_LOW_RATING || error_code == MPM_EMPTY_PATTERN)
            continue;
        if (error_code != MPM_NO_ERROR)
            goto leave;

        total_cover = update_strengths(&arena, max, rule_strength);
#if defined MPM_VERBOSE && MPM_VERBOSE
        if (flags & MPM_COMPILE_RULES_VERBOSE) {
            printf("%d (%d new) rules are covered by ", total_cover, new_cover);
            print_pattern(max);
        }
#endif
        i--;
    } while (i > 0);

#if defined MPM_VERBOSE && MPM_VERBOSE
    if (flags & MPM_COMPILE_RULES_VERBOSE)
        printf("\n%d (%f%%) rules (from %d) are covered.\n\n", all_cover, (float)all_cover * 100.0 / (float)rule_count, rule_count);
#endif

    if (!arena.re_count) {
        error_code = MPM_EMPTY_PATTERN;
        goto leave;
    }

    rule_list = compute_rule_list(arena.first_re, rule_count, consumed_memory);
    if (!rule_list)
        goto leave;

    items = create_items(arena.first_re, arena.re_count);
    if (!items)
        goto leave;

#if defined MPM_VERBOSE && MPM_VERBOSE
    if (flags & MPM_COMPILE_RULES_VERBOSE_STATS)
        print_arena_stats(&arena);
#endif

    /* Keep the patterns around, but free everything else. */
    arena.first_re = NULL;
    error_code = MPM_NO_ERROR;

leave:
    byte_code = byte_codes;
    while (byte_code < byte_code_end) {
        if (*byte_code)
            free(*byte_code);
        byte_code++;
    }
    free(byte_codes);
    free_arena(&arena);
    if (rule_strength)
        free(rule_strength);

    if (error_code == MPM_NO_ERROR) {
        error_code = final_phase(result_rule_list, items, arena.re_count, consumed_memory, flags);
        if (error_code == MPM_NO_ERROR) {
            (*result_rule_list)->rule_indices = rule_list;
            (*result_rule_list)->rule_count = rule_count;
            (*result_rule_list)->result_length = ((rule_count - 1) & ~0x1f) >> 3;
            (*result_rule_list)->result_last_word = (rule_count & 0x1f) == 0 ? 0xffffffff : (1 << (rule_count & 0x1f)) - 1;
        } else
            free(rule_list);
    } else {
        if (rule_list)
            free(rule_list);
    }
    return error_code;
}

#include "mpm_byte_code.c"
