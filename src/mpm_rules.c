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

typedef struct sub_pattern_list {
    struct sub_pattern_list *next;
    struct sub_pattern_list *hash_next;
    rule_index_list *rule_indices;
    struct sub_pattern_list *left_child;
    struct sub_pattern_list *right_child;
    mpm_byte_code *byte_code;
    mpm_char8 *from;
    mpm_uint32 hash;
    mpm_uint32 length;
    mpm_uint32 last_rule_index;
    float strength;
    float priority;
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
    mpm_uint32 mask;
    mpm_uint32 count;
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
        sub_pattern->hash_next = new_map[sub_pattern->hash & mask];
        new_map[sub_pattern->hash & mask] = sub_pattern;
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
    mpm_re *re;
    mpm_uint32 flags = (rule->flags & ~MPM_RULE_NEW);

    re = mpm_create();
    if (!re)
        return MPM_NO_MEMORY;

    int error_code = mpm_add(re, rule->pattern, flags | MPM_ADD_TEST_RATING);
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
    sub_pattern->last_rule_index = arena->rule_index;

    /* Mark children. */
    child = sub_pattern->left_child;
    if (child && child->last_rule_index != arena->rule_index) {
        error_code = recursive_mark(arena, child);
        if (error_code != MPM_NO_ERROR)
            return error_code;
    }

    child = sub_pattern->right_child;
    if (child && child->last_rule_index != arena->rule_index)
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
        if (sub_pattern->hash == hash && sub_pattern->length == byte_code_length
                && memcmp(sub_pattern->from, byte_code_from, byte_code_length) == 0) {
            if (sub_pattern->last_rule_index == arena->rule_index)
                return MPM_NO_ERROR;
            return recursive_mark(arena, sub_pattern);
        }
        sub_pattern = sub_pattern->hash_next;
    }

    sub_pattern = (sub_pattern_list *)arena_malloc(arena, sizeof(sub_pattern_list));
    if (!sub_pattern)
        return MPM_NO_MEMORY;
    sub_pattern->left_child = NULL;
    sub_pattern->right_child = NULL;
    sub_pattern->hash = hash;
    sub_pattern->from = byte_code_from;
    sub_pattern->byte_code = byte_code;
    sub_pattern->length = byte_code_length;
    sub_pattern->last_rule_index = arena->rule_index;
    sub_pattern->strength = 1.0;
    sub_pattern->priority = 0.0;

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
    sub_pattern->hash_next = arena->map[hash];
    arena->map[hash] = sub_pattern;
    sub_pattern->next = arena->first_pattern;
    arena->first_pattern = sub_pattern;
    arena->count++;

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
        sub_pattern->priority = sum * sub_pattern->strength;
        sub_pattern = sub_pattern->next;
    } while (sub_pattern);
}

#if defined MPM_VERBOSE && MPM_VERBOSE
static void print_pattern(sub_pattern_list *sub_pattern);
#endif

static void search_patterns(sub_pattern_list *first_sub_pattern, float *rule_strength, mpm_uint32 flags)
{
    float max_priority;
    sub_pattern_list *sub_pattern;
    sub_pattern_list *max;
    int i;

    compute_strength(first_sub_pattern, rule_strength);

    for (i = 0; i < 10; i++) {
        sub_pattern = first_sub_pattern;
        max = sub_pattern;
        max_priority = sub_pattern->priority;
        sub_pattern = sub_pattern->next;

        while (sub_pattern) {
            if (sub_pattern->priority > max_priority) {
                max = sub_pattern;
                max_priority = sub_pattern->priority;
            }
            sub_pattern = sub_pattern->next;
        }
        if (max_priority == 0.0)
            break;
        print_pattern(max);
        max->priority = 0.0;
    }
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
    printf("/ priority: %f\n", sub_pattern->priority);
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
    mpm_uint32 i, rule_count;
    float *rule_strength;
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

    rule_strength = NULL;
    arena.map = NULL;
    arena.first = (mpm_arena_fragment *)malloc(sizeof(mpm_arena_fragment));
    if (!arena.first)
        goto leave;
    arena.last = arena.first;
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
    arena.first_pattern = NULL;
    arena.count = 0;
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

        if ((arena.count << 1) >= arena.mask) {
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

    search_patterns(arena.first_pattern, rule_strength, flags);

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
