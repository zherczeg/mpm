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
#define SUB_PATTERN                     MPM_RULE_NEW

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
    mpm_cluster_item *cluster_items;
    mpm_cluster_item *cluster_item;
    mpm_re *re;
    mpm_size count = 0;
    mpm_uint32 group_id;

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

    do {
        pattern = (pattern_data *)cluster_item->data;
        if (cluster_item->group_id != group_id) {
            group_id = cluster_item->group_id;
            re = cluster_item->re;
        } else {
            if (mpm_combine(&re, cluster_item->re, 0) != MPM_NO_ERROR) {
                free(cluster_items);
                return 0;
            }
            last_pattern->next = (pattern_data *)cluster_item->data;
            pattern->flags |= SUB_PATTERN;
            pattern->re = NULL;
        }
        last_pattern = pattern;
        cluster_item++;
    } while (--count > 0);

    free(cluster_items);
    return 1;
}

static mpm_uint16 * compute_rule_list(pattern_list_item *pattern_list_begin, pattern_list_item *pattern_list_end, mpm_size rule_count, mpm_size *consumed_memory)
{
     mpm_uint16 *rule_indices;
     mpm_uint16 *rule_index;
     mpm_uint8 *touched_rules;
     pattern_list_item *pattern_list;
     pattern_data *pattern;
     pattern_data *same_pattern;
     mpm_size rule_list_size;
     mpm_uint32 priority;

     /* Calculating rule list size. */
     touched_rules = (mpm_uint8 *)malloc(rule_count);
     if (!touched_rules)
         return NULL;

     rule_list_size = 0;
     pattern_list = pattern_list_begin;
     while (pattern_list < pattern_list_end) {
         memset(touched_rules, 0, rule_count);
         pattern = pattern_list->u2.pattern;
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
         pattern_list++;
     }

     if (consumed_memory)
         *consumed_memory = sizeof(mpm_rule_list) + rule_list_size * sizeof(mpm_uint16);

     rule_indices = (mpm_uint16 *)malloc(rule_list_size * sizeof(mpm_uint16));
     if (!rule_indices) {
         free(touched_rules);
         return NULL;
     }

     rule_index = rule_indices;
     pattern_list = pattern_list_begin;
     while (pattern_list < pattern_list_end) {
         *rule_index++ = RULE_LIST_END;
         memset(touched_rules, 0, rule_count);
         pattern = pattern_list->u2.pattern;
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

         pattern_list->rule_indices = rule_index;
         pattern_list->u1.priority = priority;
         pattern = pattern_list->u2.pattern;
         do {
             same_pattern = pattern;
             do {
                 *rule_index++ = same_pattern->rule_index;
                 same_pattern = same_pattern->same_next;
             } while (same_pattern);
             pattern = pattern->next;
             *rule_index++ = pattern ? PATTERN_LIST_END : RULE_LIST_END;
         } while (pattern);

         pattern_list++;
     }

     free(touched_rules);
     return rule_indices;
}

static void heap_down(pattern_list_item *pattern_list_begin, mpm_size start, mpm_size end)
{
    pattern_list_item temp;
    mpm_size child = start * 2 + 1;

    while (child <= end) {
        if (child + 1 <= end && pattern_list_begin[child].u1.priority > pattern_list_begin[child + 1].u1.priority)
            child++;
        if (pattern_list_begin[start].u1.priority <= pattern_list_begin[child].u1.priority)
            return;
        temp = pattern_list_begin[start];
        pattern_list_begin[start] = pattern_list_begin[child];
        pattern_list_begin[child] = temp;
        start = child;
    }
}

static void heap_sort(pattern_list_item *pattern_list_begin, mpm_size pattern_list_length)
{
    pattern_list_item temp;
    mpm_size start;

    if (pattern_list_length <= 1)
        return;

    start = (pattern_list_length - 2) >> 1;
    pattern_list_length--;
    while (1) {
        heap_down(pattern_list_begin, start, pattern_list_length);
        if (start == 0)
            break;
        start--;
    }

    while (1) {
        temp = pattern_list_begin[0];
        pattern_list_begin[0] = pattern_list_begin[pattern_list_length];
        pattern_list_begin[pattern_list_length] = temp;

        if (!--pattern_list_length)
            return;
        heap_down(pattern_list_begin, 0, pattern_list_length);
    }
}

#if defined MPM_VERBOSE && MPM_VERBOSE

static void print_pattern_list(pattern_list_item *pattern_list, pattern_list_item *pattern_list_end)
{
    pattern_data *pattern;
    mpm_uint16 *rule_indices;

    while (pattern_list < pattern_list_end) {
        pattern = pattern_list->u2.pattern;
        rule_indices = pattern_list->rule_indices - 1;
        printf("\nNew %s pattern. Priority: %d [rules: %d", pattern->re ? "mpm" : "pcre", pattern_list->u1.priority, *rule_indices);
        while (*(--rule_indices) != RULE_LIST_END)
            printf(", %d", *rule_indices);
        printf("]\n");

        rule_indices = pattern_list->rule_indices;
        printf("  /%s/ in rule %d", pattern->string, *rule_indices++);
        while (1) {
            if (*rule_indices == RULE_LIST_END)
                break;
            if (*rule_indices == PATTERN_LIST_END) {
                rule_indices++;
                pattern = pattern->next;
                printf("\n  /%s/ in rule %d", pattern->string, *rule_indices);
            } else
                printf(", %d", *rule_indices);
            rule_indices++;
        }
        printf("\n");
        pattern_list++;
    }
    printf("\n");
}

#endif

/* ----------------------------------------------------------------------- */
/*                                 Main function.                          */
/* ----------------------------------------------------------------------- */

int mpm_compile_rules(mpm_rule_pattern *rules, mpm_size no_rule_patterns, mpm_rule_list **result_rule_list, mpm_size *consumed_memory, mpm_uint32 flags)
{
    pattern_data *pattern_list;
    pattern_data *pattern_list_end;
    pattern_data *pattern;
    pattern_data **pattern_hash;
    mpm_rule_list *rule_list;
    pattern_list_item *pattern_reference;
    mpm_uint16 *rule_indices;
    mpm_size pattern_hash_mask;
    mpm_size rule_count;
    mpm_size last_consumed_memory;
    mpm_size pattern_list_length;
    mpm_rule_pattern *rules_end;
    mpm_re *re;
    int result;

    if (!no_rule_patterns || !result_rule_list)
        return MPM_INVALID_ARGS;
    *result_rule_list = NULL;

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
    if (rules[0].flags & MPM_RULE_NEW)
        rule_count--;

    re = NULL;
    while (rules < rules_end) {
        /* Add a new item. */
        if (rules->flags & MPM_RULE_NEW)
            rule_count++;

        if (!re) {
            re = mpm_create();
            if (!re) {
                free_pattern_list(pattern_list, pattern_list_end);
                free(pattern_hash);
                return MPM_NO_MEMORY;
            }
        }

        pattern_list_end->flags = rules->flags & ~MPM_RULE_NEW;
        pattern_list_end->rule_index = rule_count;
        pattern_list_end->next = NULL;
        pattern_list_end->same_next = NULL;
        pattern_list_end->string = rules->pattern;
        pattern_list_end->re = NULL;

        if (!(flags & MPM_COMPILE_RULES_PCRE) || GET_FIXED_SIZE(pattern_list_end->flags))
            result = mpm_add(re, rules->pattern, pattern_list_end->flags | MPM_ADD_TEST_RATING);
        else
            result = MPM_UNSUPPORTED_PATTERN;

        switch (result) {
        case MPM_NO_ERROR:
            pattern_list_end->re = re;
            pattern_list_end->length = mpm_private_get_pattern_size(re->compile.patterns) - sizeof(mpm_re_pattern) + sizeof(mpm_uint32);
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
    if (rule_count >= PATTERN_LIST_END) {
        free_pattern_list(pattern_list, pattern_list_end);
        return MPM_PATTERN_LIMIT;
    }

    /* Supported patterns are passed to the clustering algorithm. */
    if (!clustering(pattern_list, pattern_list_end, flags)) {
        free_pattern_list(pattern_list, pattern_list_end);
        return MPM_NO_MEMORY;
    }

    /* Ordering by priority level. */
    pattern = pattern_list;
    pattern_list_length = 0;
    while (pattern < pattern_list_end) {
        if (!(pattern->flags & SUB_PATTERN))
            pattern_list_length++;
        pattern++;
    }

    rule_list = (mpm_rule_list *)malloc(sizeof(mpm_rule_list) + (pattern_list_length - 1) * sizeof(pattern_list_item));
    if (!rule_list) {
        free_pattern_list(pattern_list, pattern_list_end);
        return MPM_NO_MEMORY;
    }

    pattern_reference = rule_list->pattern_list;
    pattern = pattern_list;
    while (pattern < pattern_list_end) {
        if (!(pattern->flags & SUB_PATTERN)) {
            pattern_reference->u2.pattern = pattern;
            pattern_reference++;
        }
        pattern++;
    }

    rule_indices = compute_rule_list(rule_list->pattern_list, rule_list->pattern_list + pattern_list_length, rule_count, consumed_memory);
    if (!rule_indices) {
        free(rule_list);
        free_pattern_list(pattern_list, pattern_list_end);
        return MPM_NO_MEMORY;
    }

    heap_sort(rule_list->pattern_list, pattern_list_length);

#if defined MPM_VERBOSE && MPM_VERBOSE
    if (flags & MPM_COMPILE_RULES_VERBOSE)
        print_pattern_list(rule_list->pattern_list, rule_list->pattern_list + pattern_list_length);
#endif

    rule_list->rule_indices = rule_indices;
    rule_list->pattern_list_length = pattern_list_length;
    rule_list->rule_count = rule_count;
    rule_list->result_length = ((rule_count - 1) & ~0x1f) >> 3;
    rule_list->result_last_word = (rule_count & 0x1f) == 0 ? 0xffffffff : (1 << (rule_count & 0x1f)) - 1;

    pattern_reference = rule_list->pattern_list;
    while (pattern_list_length--) {
        if (pattern_reference->u2.pattern->re) {
            pattern_reference->u1.pcre = NULL;
            pattern_reference->u2.re = pattern_reference->u2.pattern->re;
        } else {
            pattern_reference->u1.pcre = pattern_reference->u2.pattern->string;
            pattern_reference->u2.flags = pattern_reference->u2.pattern->flags;
        }
        pattern_reference++;
    }

    free(pattern_list);

    pattern_list_length = rule_list->pattern_list_length;
    pattern_reference = rule_list->pattern_list;
    pattern_hash_mask = 0;
    while (pattern_list_length--) {
        if (pattern_reference->u1.pcre)
            pattern_hash_mask |= mpm_private_compile_pcre(pattern_reference);
        else {
            pattern_hash_mask |= (mpm_compile(pattern_reference->u2.re, &last_consumed_memory, (flags & MPM_COMPILE_RULES_VERBOSE_STATS) ? MPM_COMPILE_VERBOSE_STATS : 0) != MPM_NO_ERROR);
            if (!pattern_hash_mask && consumed_memory)
                *consumed_memory += last_consumed_memory;
        }
        pattern_reference++;
    }
    /* Any error occured. */
    if (pattern_hash_mask) {
        mpm_rule_list_free(rule_list);
        return MPM_NO_MEMORY;
    }

    *result_rule_list = rule_list;
    return MPM_NO_ERROR;
}
