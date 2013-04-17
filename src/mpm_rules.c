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

static int process_pattern(mpm_arena *arena, mpm_byte_code *byte_code, mpm_uint32 from, mpm_uint32 to, sub_pattern_list **parent)
{
    int error_code;
    mpm_char8 *byte_code_from;
    sub_pattern_list *sub_pattern;
    mpm_uint32 offset, byte_code_length;
    mpm_uint32 left_offset, right_offset;
    mpm_uint32 count1, count2;
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
            if (offset >= left_offset)
                count1++;
            if (offset < right_offset)
                count2++;
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

#if defined MPM_VERBOSE && MPM_VERBOSE
static void print_pattern(sub_pattern_list *sub_pattern);
#endif

static void compute_strength(sub_pattern_list *sub_pattern, float *rule_strength)
{
    rule_index_list *index;
    float sum;

    do {
        sum = 0.0;
        index = sub_pattern->rule_indices;
        do {
            sum += rule_strength[index->rule_index];
            index = index->next;
        } while (index);
        sub_pattern->u.s2.priority = sum * sub_pattern->u.s2.strength * ((float)(sub_pattern->length - 1) / 4.0 + 1.0);
        sub_pattern = sub_pattern->next;
    } while (sub_pattern);
}

static mpm_uint32 recursive_distance_down(sub_pattern_list *sub_pattern, mpm_uint32 run)
{
    mpm_uint32 value, left_child = (0 << 12), right_child = (0 << 12);

    if ((sub_pattern->u.s2.distance & 0xfff) == run)
        return sub_pattern->u.s2.distance & ~0xfff;

    if (sub_pattern->left_child)
        left_child = recursive_distance_down(sub_pattern->left_child, run);

    if (sub_pattern->right_child)
        right_child = recursive_distance_down(sub_pattern->right_child, run);

    if (left_child == (0 << 12) && right_child == (0 << 12))
        value = (0 << 12);
    else if (left_child == (0 << 12) || (left_child > right_child && right_child != (0 << 12)))
        value = right_child + (1 << 12);
    else
        value = left_child + (1 << 12);

    if (value > (0 << 12)) {
        sub_pattern->u.s2.strength *= 0.75;
    }

    sub_pattern->u.s2.distance = run | value;
    return value;
}

static void recursive_distance_up(sub_pattern_list *sub_pattern)
{
    sub_pattern->u.s2.strength *= 0.25;

    if (sub_pattern->left_child)
        recursive_distance_up(sub_pattern->left_child);
    if (sub_pattern->right_child)
        recursive_distance_up(sub_pattern->right_child);
}

static mpm_uint32 update_strengths(sub_pattern_list *current, sub_pattern_list *sub_pattern, float *rule_strength, mpm_uint32 run, mpm_uint32 *new_cover_ptr)
{
    rule_index_list *rule_index = sub_pattern->rule_indices;
    mpm_uint32 new_cover = 0, total_cover = 0;

    do {
        total_cover++;
        if (rule_strength[rule_index->rule_index] == 1.0)
            new_cover++;
        rule_strength[rule_index->rule_index] *= 0.25;
        rule_index = rule_index->next;
    } while (rule_index);

    sub_pattern->u.s2.distance = run | (1 << 12);
    sub_pattern->u.s2.strength = 0.0;

    do {
        recursive_distance_down(current, run);
        current = current->next;
    } while (current);

    recursive_distance_up(sub_pattern);

    *new_cover_ptr = new_cover;
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
    arena->re_count ++;
    return MPM_NO_ERROR;
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
        printf("%.*s", byte_code_data[offset].pattern_length, pattern + byte_code_data[offset].pattern_offset);
        offset += byte_code_data[offset].byte_code_length;
    }
    printf("/ priority: %f strength: %f\n", sub_pattern->u.s2.priority, sub_pattern->u.s2.strength);
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

int mpm_compile_rules(mpm_rule_pattern *rules, mpm_size no_rule_patterns, mpm_rule_list **result_rule_list, mpm_size *consumed_memory, mpm_uint32 flags)
{
    mpm_byte_code **byte_codes;
    mpm_byte_code **byte_code;
    mpm_byte_code **byte_code_end;
    sub_pattern_list *pattern;
    sub_pattern_list *max;
    mpm_uint32 i, rule_count;
    mpm_uint32 new_cover, total_cover;
    float *rule_strength;
    float max_priority;
    int error_code = MPM_NO_MEMORY;
    mpm_arena arena;

    if (!no_rule_patterns || !result_rule_list)
        return MPM_INVALID_ARGS;
    *result_rule_list = NULL;

    byte_codes = (mpm_byte_code **)malloc(no_rule_patterns * sizeof(mpm_byte_code *));
    if (!byte_codes)
        return MPM_NO_MEMORY;
    byte_code_end = byte_codes + no_rule_patterns;
    memset(byte_codes, 0, no_rule_patterns * sizeof(mpm_byte_code *));

    /* Arena initialization. */
    rule_strength = NULL;
    arena.map = NULL;
    arena.first_re = NULL;
    arena.first_pattern = NULL;

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

#if defined MPM_VERBOSE && MPM_VERBOSE
    if (flags & MPM_COMPILE_RULES_VERBOSE_STATS)
        print_arena_stats(&arena);
#endif

    free(arena.map);
    arena.map = NULL;

    rule_strength = (float *)malloc(rule_count * sizeof(float));
    if (!rule_strength)
        goto leave;

    for (i = 0; i < rule_count; i++)
        rule_strength[i] = 1.0;

    pattern = arena.first_pattern;
    while (pattern) {
        pattern->u.s2.strength = 1.0;
        pattern->u.s2.distance = 0;
        pattern = pattern->next;
    }

    for (i = 0; i < 4; i++) {
        compute_strength(arena.first_pattern, rule_strength);

        pattern = arena.first_pattern;
        max = pattern;
        max_priority = pattern->u.s2.priority;
        pattern = pattern->next;

        while (pattern) {
            if (pattern->u.s2.priority > max_priority) {
                max = pattern;
                max_priority = pattern->u.s2.priority;
            }
            pattern = pattern->next;
        }
        if (max_priority == 0.0)
            break;

        error_code = try_compile(&arena, max);
        printf("compile: %d ", error_code);
        print_pattern(max);
        max->u.s2.strength = 0.0;
        if (error_code == MPM_TOO_LOW_RATING || error_code == MPM_EMPTY_PATTERN) {
            i--;
            continue;
        }
        if (error_code != MPM_NO_ERROR)
            goto leave;

        total_cover = update_strengths(arena.first_pattern, max, rule_strength, i + 1, &new_cover);
        printf("  total cover: %d new cover: %d\n", total_cover, new_cover);
    }

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
    return error_code;
}

#include "mpm_byte_code.c"
