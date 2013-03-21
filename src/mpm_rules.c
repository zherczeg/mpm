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
typedef struct pattern_data {
    mpm_uint32 flags;
    mpm_uint32 rule_index;
    mpm_size length;
    mpm_uint32 hash;
    struct pattern_data *next;
    struct pattern_data *same_next;
    mpm_char8 *string;
    mpm_re *re;
} pattern_data;

/* Temporary data structure for ordering the patterns. */
typedef struct pattern_reference_data {
    mpm_uint32 priority;
    mpm_uint16 *rule_list;
    pattern_data *pattern;
} pattern_reference_data;

static void free_pattern_list(pattern_data *pattern_list, pattern_data *pattern_list_end)
{
    pattern_data *pattern = pattern_list;
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

static void insert_pattern(pattern_data *pattern, pattern_data **pattern_hash)
{
    /* Hash table insert. */
    int compare;
    pattern_data *pattern_list = *pattern_hash;

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

static int clustering(pattern_data *pattern_list, pattern_data *pattern_list_end, mpm_uint32 flags)
{
    /* Creates regular expression groups. */
    pattern_data *pattern;
    pattern_data *last_pattern;
    pattern_data *last_head_pattern;
    mpm_cluster_item *cluster_items;
    mpm_cluster_item *cluster_item;
    mpm_re *re;
    mpm_size count = 0;
    mpm_uint32 group_id;
    mpm_uint32 population_count;
    mpm_re *small_pattern_re;
    pattern_data *small_pattern_last;
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
        pattern = (pattern_data *)cluster_item->data;
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
            last_pattern->next = (pattern_data *)cluster_item->data;
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

static mpm_uint16 * compute_rule_list(pattern_reference_data *pattern_references, pattern_reference_data *pattern_references_end, mpm_size rule_count)
{
     mpm_uint16 *rule_indices;
     mpm_uint16 *rule_index;
     mpm_uint8 *touched_rules;
     pattern_reference_data *pattern_reference;
     pattern_data *pattern;
     pattern_data *same_pattern;
     mpm_size rule_list_size;
     mpm_uint32 priority;

     /* Calculating rule list size. */
     touched_rules = (mpm_uint8 *)malloc(rule_count);
     if (!touched_rules)
         return NULL;

     rule_list_size = 0;
     pattern_reference = pattern_references;
     while (pattern_reference < pattern_references_end) {
         memset(touched_rules, 0, rule_count);
         pattern = pattern_reference->pattern;
         do {
             same_pattern = pattern;
             do {
                 if (!touched_rules[same_pattern->rule_index]) {
                     rule_list_size++;
                     touched_rules[same_pattern->rule_index] = 1;
                 }
                 rule_list_size++;
                 same_pattern = same_pattern->same_next;
             } while (same_pattern);
             pattern = pattern->next;
             rule_list_size++;
         } while (pattern);
         rule_list_size++;
         pattern_reference++;
     }

     rule_indices = (mpm_uint16 *)malloc(rule_list_size * sizeof(mpm_uint16 *));
     if (!rule_indices) {
         free(touched_rules);
         return NULL;
     }

     rule_index = rule_indices;
     pattern_reference = pattern_references;
     while (pattern_reference < pattern_references_end) {
         *rule_index++ = RULE_LIST_END;
         memset(touched_rules, 0, rule_count);
         pattern = pattern_reference->pattern;
         priority = 0;
         do {
             same_pattern = pattern;
             do {
                 if (!touched_rules[same_pattern->rule_index]) {
                     *rule_index++ = same_pattern->rule_index;
                     priority++;
                     touched_rules[same_pattern->rule_index] = 1;
                 }
                 same_pattern = same_pattern->same_next;
             } while (same_pattern);
             pattern = pattern->next;
         } while (pattern);

         pattern_reference->rule_list = rule_index;
         pattern_reference->priority = priority;
         pattern = pattern_reference->pattern;
         do {
             same_pattern = pattern;
             do {
                 *rule_index++ = same_pattern->rule_index;
                 same_pattern = same_pattern->same_next;
             } while (same_pattern);
             pattern = pattern->next;
             *rule_index++ = pattern ? PATTERN_LIST_END : RULE_LIST_END;
         } while (pattern);

         pattern_reference++;
     }

     free(touched_rules);
     return rule_indices;
}

static void heap_down(pattern_reference_data *pattern_references, mpm_size start, mpm_size end)
{
    pattern_reference_data temp;
    mpm_size child = start * 2 + 1;

    while (child <= end) {
        if (child + 1 <= end && pattern_references[child].priority > pattern_references[child + 1].priority)
            child++;
        if (pattern_references[start].priority <= pattern_references[child].priority)
            return;
        temp = pattern_references[start];
        pattern_references[start] = pattern_references[child];
        pattern_references[child] = temp;
        start = child;
    }
}

static void heap_sort(pattern_reference_data *pattern_references, mpm_size pattern_reference_count)
{
    pattern_reference_data temp;
    mpm_size start;

    if (pattern_reference_count <= 1)
        return;

    start = (pattern_reference_count - 2) >> 1;
    pattern_reference_count--;
    while (1) {
        heap_down(pattern_references, start, pattern_reference_count);
        if (start == 0)
            break;
        start--;
    }

    while (1) {
        temp = pattern_references[0];
        pattern_references[0] = pattern_references[pattern_reference_count];
        pattern_references[pattern_reference_count] = temp;

        if (!--pattern_reference_count)
            return;
        heap_down(pattern_references, 0, pattern_reference_count);
    }
}

#if defined MPM_VERBOSE && MPM_VERBOSE

static void print_pattern_list(pattern_reference_data *pattern_references, pattern_reference_data *pattern_references_end)
{
    pattern_data *pattern;
    mpm_uint16 *rule_list;

    while (pattern_references < pattern_references_end) {
        pattern = pattern_references->pattern;
        rule_list = pattern_references->rule_list - 1;
        printf("\nNew %s pattern. Priority: %d [rules: %d", pattern->re ? "mpm" : "pcre", pattern_references->priority, *rule_list);
        while (*(--rule_list) != RULE_LIST_END)
            printf(", %d", *rule_list);
        printf("]\n");

        rule_list = pattern_references->rule_list;
        printf("  /%s/ in rule %d", pattern->string, *rule_list++);
        while (1) {
            if (*rule_list == RULE_LIST_END)
                break;
            if (*rule_list == PATTERN_LIST_END) {
                rule_list++;
                pattern = pattern->next;
                printf("\n  /%s/ in rule %d", pattern->string, *rule_list);
            } else
                printf(", %d", *rule_list);
            rule_list++;
        }
        printf("\n");
        pattern_references++;
    }
    printf("\n");
}

#endif

/* ----------------------------------------------------------------------- */
/*                                 Main function.                          */
/* ----------------------------------------------------------------------- */

int mpm_compile_rules(mpm_rule_pattern *rules, mpm_size no_rule_patterns, mpm_uint32 flags)
{
    pattern_data *pattern_list;
    pattern_data *pattern_list_end;
    pattern_data *pattern;
    pattern_data **pattern_hash;
    pattern_reference_data *pattern_references;
    pattern_reference_data *pattern_reference;
    mpm_uint16 *rule_indices;
    mpm_size pattern_hash_mask;
    mpm_size rule_count;
    mpm_size pattern_reference_count;
    mpm_rule_pattern *rules_end;
    mpm_re *re;

    if (!no_rule_patterns)
        return MPM_INVALID_ARGS;

    /* Compile patterns if possible. */
    pattern_list = (pattern_data *)malloc(no_rule_patterns * sizeof(pattern_data));
    if (!pattern_list)
        return MPM_NO_MEMORY;

    pattern_hash_mask = 1;
    while (pattern_hash_mask < no_rule_patterns)
        pattern_hash_mask <<= 1;
    if (pattern_hash_mask > 4)
        pattern_hash_mask >>= 1;

    pattern_hash = (pattern_data **)malloc(pattern_hash_mask * sizeof(pattern_data *));
    if (!pattern_hash) {
        free(pattern_list);
        return MPM_NO_MEMORY;
    }

    memset(pattern_hash, 0, pattern_hash_mask * sizeof(pattern_data *));
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

    /* Ordering by priority level. */
    pattern = pattern_list;
    pattern_reference_count = 0;
    while (pattern < pattern_list_end) {
        if (!(pattern->flags & SUB_PATTERN))
            pattern_reference_count++;
        pattern++;
    }

    pattern_references = (pattern_reference_data *)malloc(pattern_reference_count * sizeof(pattern_reference_data));
    if (!pattern_references) {
        free_pattern_list(pattern_list, pattern_list_end);
        return MPM_NO_MEMORY;
    }

    pattern_reference = pattern_references;
    pattern = pattern_list;
    while (pattern < pattern_list_end) {
        if (!(pattern->flags & SUB_PATTERN)) {
            pattern_reference->pattern = pattern;
            pattern_reference++;
        }
        pattern++;
    }

    rule_indices = compute_rule_list(pattern_references, pattern_references + pattern_reference_count, rule_count);
    if (!rule_indices) {
        free(pattern_references);
        free_pattern_list(pattern_list, pattern_list_end);
        return MPM_NO_MEMORY;
    }

    heap_sort(pattern_references, pattern_reference_count);

#if defined MPM_VERBOSE && MPM_VERBOSE
    if (flags & MPM_COMPILE_RULES_VERBOSE)
        print_pattern_list(pattern_references, pattern_references + pattern_reference_count);
#endif

    /* TODO: Unsupported patterns are compiled by PCRE. */

    free(pattern_references);
    free(pattern_list);
    return MPM_NO_ERROR;
}
