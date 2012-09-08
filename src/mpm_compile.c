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
/*                        Bitset management functions.                     */
/* ----------------------------------------------------------------------- */

typedef struct mpm_hashitem {
    struct mpm_hashitem *next;
    struct mpm_hashitem *next_unprocessed;
    uint32_t hash;
    uint32_t id;
    uint32_t bitset[1];
} mpm_hashitem;

/* Items can only be added, but they never removed. */

typedef struct mpm_hashmap {
    /* The map is optimized for 32 bit words.
       length measured in 32 bit words, size measured in bytes. */
    uint32_t key_length;
    uint32_t value_length;
    uint32_t key_size;
    uint32_t record_size;
    uint32_t allocation_size;
    uint32_t item_count;
    /* The mask must have the value of 2^n-1 */
    uint32_t mask;
    mpm_hashitem **buckets;
    /* This bitset is added to the list by hashmap_insert. */
    uint32_t *current;

    /* Other global variables. */
    /* Starting bitset. */
    uint32_t *start;
    /* Not processed items. */
    struct mpm_hashitem *next_unprocessed;
} mpm_hashmap;

#define DEFAULT_MAP_SIZE 1024

static int hashmap_init(mpm_hashmap *map, uint32_t key_length, uint32_t value_length)
{
    if (key_length <= 0)
        key_length = 1;
    map->key_length = (key_length + 31) >> 5;

    if (value_length <= 0)
        value_length = 1;
    map->value_length = (key_length + 31) >> 5;

    map->key_size = map->key_length * sizeof(uint32_t);
    map->record_size = (map->key_length + map->value_length) * sizeof(uint32_t);
    map->allocation_size = sizeof(mpm_hashitem) + map->record_size - sizeof(uint32_t);

    map->item_count = 0;
    map->mask = DEFAULT_MAP_SIZE - 1;
    map->next_unprocessed = NULL;

    map->buckets = NULL;
    map->current = NULL;
    map->start = NULL;

    /* Allocating memory. */
    map->buckets = (mpm_hashitem **)malloc(DEFAULT_MAP_SIZE * sizeof(mpm_hashitem *));
    if (!map->buckets)
        return 1;
    memset(map->buckets, 0, DEFAULT_MAP_SIZE * sizeof(mpm_hashitem *));

    map->current = (uint32_t *)malloc(map->record_size);
    if (!map->current)
        return 1;

    map->start = (uint32_t *)malloc(map->record_size);
    if (!map->start)
        return 1;

    return 0;
}

static void hashmap_free(mpm_hashmap *map)
{
    mpm_hashitem *item;
    mpm_hashitem *next;
    mpm_hashitem **buckets;
    uint32_t i;

    if (map->buckets) {
        buckets = map->buckets;
        for (i = map->mask + 1; i > 0; i--) {
            item = buckets[i - 1];
            while (item) {
                next = item->next;
                free(item);
                item = next;
            }
        }
        free(map->buckets);
    }

    if (map->current)
        free(map->current);
    if (map->start)
        free(map->start);
}

static uint32_t hashmap_insert(mpm_hashmap *map)
{
    uint32_t key_length = map->key_length;
    uint32_t hash = 0xaaaaaaaa;
    uint8_t *data_ptr = (uint8_t*)map->current;
    uint32_t *current = map->current;
    mpm_hashitem *item, *next;
    uint32_t new_mask;
    mpm_hashitem **new_buckets;
    mpm_hashitem **buckets = map->buckets;
    int i;

    /* Hash from Arash Partow. */
    key_length <<= 1;
    do {
        // Processing two bytes in one step.
        hash ^= (hash << 7) ^ ((*data_ptr) * (hash >> 3));
        hash ^= ~((hash << 11) + ((*data_ptr) ^ (hash >> 5)));
        data_ptr++;
    } while (key_length--);

    /* Search this item in the list. */
    item = buckets[hash & map->mask];
    key_length = map->key_length << 2;
    while (item) {
        if (item->hash == hash && memcmp(current, item->bitset, key_length) == 0)
            return item->id;
        item = item->next;
    }

    /* Inserting a new item. */
    item = (mpm_hashitem *)malloc(map->allocation_size);
    if (!item)
        return DFA_LAST_TERM;

    item->next = buckets[hash & map->mask];
    buckets[hash & map->mask] = item;
    item->next_unprocessed = map->next_unprocessed;
    map->next_unprocessed = item;
    item->hash = hash;
    item->id = map->item_count;
    memcpy(item->bitset, current, map->record_size);
    map->item_count++;

    if (map->item_count < map->mask || map->mask > 0x10000000)
        return item->id;

    /* Resize the hash array. */
    new_mask = (map->mask << 1) | 0x1;
    new_buckets = (mpm_hashitem **)malloc((new_mask + 1) * sizeof(mpm_hashitem *));
    if (!new_buckets)
        return DFA_LAST_TERM;
    memset(new_buckets, 0, (new_mask + 1) * sizeof(mpm_hashitem *));

    /* Copy items to the new hash. */
    for (i = 0; i <= map->mask; i++) {
        item = buckets[i];
        while (item) {
            next = item->next;
            item->next = new_buckets[item->hash & new_mask];
            new_buckets[item->hash & new_mask] = item;
            item = next;
        }
    }
    free(buckets);
    map->mask = new_mask;
    map->buckets = new_buckets;
    return item->id;
}

#if defined MPM_VERBOSE && MPM_VERBOSE
static void hashmap_stats(mpm_hashmap *map)
{
    mpm_hashitem *item;
    mpm_hashitem **buckets = map->buckets;
    uint32_t mask = map->mask;
    int count, max = 0;
    uint32_t i;

    if (((mask + 1) & mask) != 0)
        printf("ERROR: Mask is not (2^n)-1\n");

    for (i = mask + 1; i > 0; i--) {
        item = buckets[i - 1];
        count = 0;
        while (item) {
            if ((item->hash & mask) != i - 1)
                printf("ERROR: Wrong hash code\n");
            count++;
            item = item->next;
        }
        if (count > max)
            max = count;
    }
    printf("Hashmap statistics: items: %d max bucket: %d \n", map->item_count, max);
}
#endif

/* ----------------------------------------------------------------------- */
/*                               Core functions.                           */
/* ----------------------------------------------------------------------- */

int mpm_compile(mpm_re *re)
{
    mpm_hashmap map_data;
    mpm_hashmap *map = &map_data;
    mpm_re_pattern *pattern;
    uint32_t *word_code;
    uint32_t *current;
    uint32_t *start;
    uint32_t record_size;

    if (re->next_id == 0)
        return MPM_RE_ALREADY_COMPILED;

    if (hashmap_init(map, re->next_term_index, re->next_id - 1)) {
        hashmap_free(map);
        return MPM_NO_MEMORY;
    }

    record_size = map->record_size;
    start = map->start;
    current = map->current;

    memset(start, 0, record_size);
    pattern = re->patterns;
    while (pattern) {
        word_code = pattern->word_code + pattern->term_range_size + 1;
        while (word_code[0] != DFA_LAST_TERM) {
            DFA_SETBIT(start, word_code[0]);
            word_code++;
        }
        pattern = pattern->next;
    }

    memcpy(current, start, record_size);
    hashmap_insert(map);



    hashmap_free(map);

    re->next_id = 0;
    return MPM_NO_ERROR;
}
