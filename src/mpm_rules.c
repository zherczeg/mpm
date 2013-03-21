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
/*                             Utility functions.                          */
/* ----------------------------------------------------------------------- */

/* Patterns whose are part of other pattern chain lists. */
#define SUB_PATTERN                     MPM_NEW_RULE

/* Temporary data structure for processing the patterns. */
typedef struct internal_pattern {
    mpm_uint32 flags;
    mpm_uint32 rule_index;
    mpm_size length;
    mpm_uint32 hash;
    struct internal_pattern *next;
    struct internal_pattern *same_next;
    mpm_char8 *string;
    mpm_re *re;
} internal_pattern;

static void free_pattern_list(internal_pattern *pattern_list, internal_pattern *pattern_list_end)
{
    internal_pattern *pattern = pattern_list;
    while (pattern < pattern_list_end) {
        if (pattern->re)
            mpm_free(pattern->re);
        pattern++;
    }
    free(pattern_list);
}

static mpm_size get_pattern_size(mpm_re_pattern *pattern)
{
     /* Get the total size in bytes of the DFA. */
     mpm_uint32 *word_code = pattern->word_code;
     word_code += pattern->word_code[pattern->term_range_size - 1];
     word_code += CHAR_SET_SIZE + 1;

     while (*word_code != DFA_NO_DATA)
         word_code++;

     word_code++;
     return (word_code - pattern->word_code) << 2;
}

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

static void insert_pattern(internal_pattern *pattern, internal_pattern **pattern_hash)
{
    /* Hash table insert. */
    int compare;
    internal_pattern *pattern_list = *pattern_hash;

    while (pattern_list) {
        if (pattern_list->hash == pattern->hash
                && pattern_list->length == pattern->length
                && pattern_list->flags == pattern->flags) {

            if (pattern->re)
                compare = memcmp(pattern->re->compile.patterns->word_code, pattern_list->re->compile.patterns->word_code, pattern->length);
            else
                compare = memcmp(pattern->string, pattern_list->string, pattern->length);

            if (compare == 0) {
                /* Insert as first. */
                pattern->flags |= SUB_PATTERN;
                pattern->same_next = pattern_list->same_next;
                pattern_list->same_next = pattern;
                if (pattern->re) {
                    mpm_free(pattern->re);
                    pattern->re = NULL;
                }
                return;
            }
        }
        pattern_list = pattern_list->next;
    }

    pattern->next = *pattern_hash;
    *pattern_hash = pattern;
}

static int clustering(internal_pattern *pattern_list, internal_pattern *pattern_list_end, mpm_uint32 flags)
{
    /* Creates regular expression groups. */
    internal_pattern *pattern;
    internal_pattern *last_pattern;
    internal_pattern *last_head_pattern;
    mpm_cluster_item *cluster_items;
    mpm_cluster_item *cluster_item;
    mpm_re *re;
    mpm_size count = 0;
    mpm_uint32 group_id;
    mpm_uint32 population_count;
    mpm_re *small_pattern_re;
    internal_pattern *small_pattern_last;
    mpm_uint32 small_population_count;

    pattern = pattern_list;
    while (pattern < pattern_list_end) {
        if (pattern->re)
            count++;
        pattern->next = NULL;
        pattern++;
    }

    if (count == 0)
        return 1;

    cluster_items = (mpm_cluster_item *)malloc(count * sizeof(mpm_cluster_item));
    if (!cluster_items)
        return 0;

    cluster_item = cluster_items;
    pattern = pattern_list;
    while (pattern < pattern_list_end) {
        if (pattern->re) {
            cluster_item->re = pattern->re;
            cluster_item->data = pattern;
            cluster_item++;
        }
        pattern++;
    }

    if (mpm_clustering(cluster_items, count, (flags & MPM_COMPILE_RULES_VERBOSE) ? MPM_CLUSTERING_VERBOSE : 0) != MPM_NO_ERROR) {
        free(cluster_items);
        return 0;
    }

    cluster_item = cluster_items;
    group_id = (mpm_uint32)-1;
    small_pattern_re = NULL;
    population_count = 32;

    do {
        pattern = (internal_pattern *)cluster_item->data;
        if (cluster_item->group_id != group_id) {
            if (population_count < 3) {
                /* Joining very small groups. */
                if (small_pattern_re) {
                    if (mpm_combine(small_pattern_re, last_head_pattern->re) != MPM_NO_ERROR) {
                        free(cluster_items);
                        return 0;
                    }
                    small_pattern_last->next = last_head_pattern;
                    last_head_pattern->flags |= SUB_PATTERN;
                    last_head_pattern->re = NULL;
                    small_population_count += population_count;
                    if (small_population_count >= 3)
                        small_pattern_re = NULL;
                } else {
                    small_pattern_re = last_head_pattern->re;
                    small_population_count = population_count;
                }
                small_pattern_last = last_pattern;
            }
            group_id = cluster_item->group_id;
            re = cluster_item->re;
            population_count = 1;
            last_head_pattern = pattern;
        } else {
            if (mpm_combine(re, cluster_item->re) != MPM_NO_ERROR) {
                free(cluster_items);
                return 0;
            }
            last_pattern->next = (internal_pattern *)cluster_item->data;
            pattern->flags |= SUB_PATTERN;
            pattern->re = NULL;
            population_count++;
        }
        last_pattern = pattern;
        cluster_item++;
    } while (--count > 0);

    if (population_count < 3 && small_pattern_re) {
        /* Joining very small groups. */
        if (mpm_combine(small_pattern_re, last_head_pattern->re) != MPM_NO_ERROR) {
            free(cluster_items);
            return 0;
        }

        small_pattern_last->next = last_head_pattern;
        last_head_pattern->flags |= SUB_PATTERN;
        last_head_pattern->re = NULL;
    }

    free(cluster_items);
    return 1;
}

#if defined MPM_VERBOSE && MPM_VERBOSE

static void print_pattern_list(internal_pattern *pattern_list, internal_pattern *pattern_list_end)
{
     internal_pattern *pattern;
     internal_pattern *same_pattern;

     while (pattern_list < pattern_list_end) {
         if (!(pattern_list->flags & SUB_PATTERN)) {
             pattern = pattern_list;
             printf("\nNew %s pattern:\n", pattern->re ? "mpm" : "pcre");
             do {
                 printf("  /%s/ in rule %d", pattern->string, pattern->rule_index);
                 same_pattern = pattern->same_next;
                 while (same_pattern) {
                     printf(", %d", same_pattern->rule_index);
                     same_pattern = same_pattern->same_next;
                 }
                 printf("\n");
                 pattern = pattern->next;
             } while (pattern);
         }
         pattern_list++;
     }
}

#endif

/* ----------------------------------------------------------------------- */
/*                                 Main function.                          */
/* ----------------------------------------------------------------------- */

int mpm_compile_rules(mpm_rule_pattern *rules, mpm_size no_rule_patterns, mpm_uint32 flags)
{
    mpm_uint32 rule_count;
    internal_pattern *pattern_list;
    internal_pattern *pattern_list_end;
    internal_pattern **pattern_hash;
    mpm_size pattern_hash_mask;
    mpm_rule_pattern *rules_end;
    mpm_re *re;

    if (!no_rule_patterns)
        return MPM_INVALID_ARGS;

    /* Compile patterns if possible. */
    pattern_list = (internal_pattern *)malloc(no_rule_patterns * sizeof(internal_pattern));
    if (!pattern_list)
        return MPM_NO_MEMORY;

    pattern_hash_mask = 1;
    while (pattern_hash_mask < no_rule_patterns)
        pattern_hash_mask <<= 1;
    if (pattern_hash_mask > 4)
        pattern_hash_mask >>= 1;

    pattern_hash = (internal_pattern **)malloc(pattern_hash_mask * sizeof(internal_pattern *));
    if (!pattern_hash) {
        free(pattern_list);
        return MPM_NO_MEMORY;
    }

    memset(pattern_hash, 0, pattern_hash_mask * sizeof(internal_pattern *));
    pattern_hash_mask--;

    rules_end = rules + no_rule_patterns;
    pattern_list_end = pattern_list;
    rule_count = 0;
    if (rules[0].flags & MPM_NEW_RULE)
        rule_count--;

    re = NULL;
    while (rules < rules_end) {
        /* Add a new item. */
        if (rules->flags & MPM_NEW_RULE)
            rule_count++;

        if (!re) {
            re = mpm_create();
            if (!re) {
                free_pattern_list(pattern_list, pattern_list_end);
                free(pattern_hash);
                return MPM_NO_MEMORY;
            }
        }

        pattern_list_end->flags = rules->flags & ~MPM_NEW_RULE;
        pattern_list_end->rule_index = rule_count;
        pattern_list_end->next = NULL;
        pattern_list_end->same_next = NULL;
        pattern_list_end->string = rules->pattern;
        pattern_list_end->re = NULL;
        switch (mpm_add(re, rules->pattern, pattern_list_end->flags | MPM_ADD_TEST_RATING)) {
        case MPM_NO_ERROR:
            pattern_list_end->re = re;
            pattern_list_end->length = get_pattern_size(re->compile.patterns);
            pattern_list_end->hash = compute_hash((mpm_uint8 *)re->compile.patterns->word_code, pattern_list_end->length);
            re = NULL;
            break;

        case MPM_TOO_LOW_RATING:
        case MPM_UNSUPPORTED_PATTERN:
            pattern_list_end->length = strlen((char *)rules->pattern);
            pattern_list_end->hash = compute_hash((mpm_uint8 *)rules->pattern, pattern_list_end->length);
            break;

        default:
            mpm_free(re);
            free_pattern_list(pattern_list, pattern_list_end);
            free(pattern_hash);
            return MPM_INVALID_PATTERN;
        }

        /* Check whether it is already there. */
        insert_pattern(pattern_list_end, pattern_hash + (pattern_list_end->hash & pattern_hash_mask));

        rules++;
        pattern_list_end++;
    }

    if (re)
        mpm_free(re);
    free(pattern_hash);

    rule_count++;

    /* Supported patterns are passed to the clustering algorithm. */
    if (!clustering(pattern_list, pattern_list_end, flags)) {
        free_pattern_list(pattern_list, pattern_list_end);
        return MPM_NO_MEMORY;
    }

#if defined MPM_VERBOSE && MPM_VERBOSE
    if (flags & MPM_COMPILE_RULES_VERBOSE)
        print_pattern_list(pattern_list, pattern_list_end);
#endif

    /* Ordering by priority level. */

    /* TODO: Unsupported patterns are compiled by PCRE. */

    free(pattern_list);
    return MPM_NO_ERROR;
}
