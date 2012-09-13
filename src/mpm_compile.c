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
/*                        Hashmap management functions.                    */
/* ----------------------------------------------------------------------- */

typedef struct mpm_hashitem {
    struct mpm_hashitem *next;
    struct mpm_hashitem *next_unprocessed;
    mpm_offset_map *offset_map;
    uint32_t hash;
    uint32_t id;
    uint32_t offset_map_size;
    /* Variable length member. */
    uint32_t term_set[1];
} mpm_hashitem;

typedef struct mpm_id_offset_map {
    struct mpm_hashitem *item;
    uint32_t offset;
} mpm_id_offset_map;

/* Items can only be added, but they never removed. */

typedef struct mpm_hashmap {
    /* The map is optimized for 32 bit words.
       length measured in 32 bit words, size measured in bytes. */
    uint32_t term_set_length;
    uint32_t end_state_set_length;
    uint32_t record_size;
    uint32_t allocation_size;
    uint32_t item_count;
    /* The mask must have the value of 2^n-1 */
    uint32_t mask;
    mpm_hashitem **buckets;
    /* This term_set is added to the list by hashmap_insert. */
    uint32_t *current;

    /* Other global variables. */
    /* Starting term_set. */
    uint32_t *start;
    uint32_t **term_map;
    uint32_t **term_list;
    mpm_id_offset_map *id_offset_map;
    /* Not processed items. */
    mpm_hashitem *next_unprocessed;
} mpm_hashmap;

#define DEFAULT_MAP_SIZE 1024

static int hashmap_init(mpm_hashmap *map, uint32_t term_set_length, uint32_t end_state_set_length)
{
    uint32_t no_terms = term_set_length;

    if (term_set_length <= 0)
        term_set_length = 1;
    map->term_set_length = (term_set_length + 31) >> 5;

    if (end_state_set_length <= 0)
        end_state_set_length = 1;
    map->end_state_set_length = (term_set_length + 31) >> 5;

    map->record_size = (map->term_set_length + map->end_state_set_length) * sizeof(uint32_t);
    map->allocation_size = sizeof(mpm_hashitem) + map->record_size - sizeof(uint32_t);

    map->item_count = 0;
    map->mask = DEFAULT_MAP_SIZE - 1;
    map->next_unprocessed = NULL;

    map->buckets = NULL;
    map->current = NULL;
    map->start = NULL;
    map->term_map = NULL;
    map->term_list = NULL;
    map->id_offset_map = NULL;

    /* Allocating memory. */
    map->buckets = (mpm_hashitem **)malloc(DEFAULT_MAP_SIZE * sizeof(mpm_hashitem *));
    if (!map->buckets)
        return 1;
    memset(map->buckets, 0, DEFAULT_MAP_SIZE * sizeof(mpm_hashitem *));

    map->current = (uint32_t *)malloc(map->record_size * 2);
    if (!map->current)
        return 1;

    map->start = map->current + (map->term_set_length + map->end_state_set_length);

    map->term_map = (uint32_t **)malloc(no_terms * sizeof(uint32_t *) * 2);
    if (!map->term_map)
        return 1;
    map->term_list = map->term_map + no_terms;

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
                if (item->offset_map)
                    free(item->offset_map);
                free(item);
                item = next;
            }
        }
        free(map->buckets);
    }

    if (map->current)
        free(map->current);
    if (map->term_map)
        free(map->term_map);
    if (map->id_offset_map)
        free(map->id_offset_map);
}

static uint32_t hashmap_insert(mpm_hashmap *map)
{
    uint32_t record_size = map->record_size;
    uint32_t hash = 0xaaaaaaaa;
    uint8_t *data_ptr = (uint8_t*)map->current;
    uint32_t *current = map->current;
    mpm_hashitem *item, *next;
    uint32_t new_mask;
    mpm_hashitem **new_buckets;
    mpm_hashitem **buckets = map->buckets;
    uint32_t id;
    int i;

    /* Hash from Arash Partow. */
    record_size >>= 1;
    do {
        // Processing two bytes in one step.
        hash ^= (hash << 7) ^ ((*data_ptr) * (hash >> 3));
        hash ^= ~((hash << 11) + ((*data_ptr) ^ (hash >> 5)));
        data_ptr++;
    } while (record_size--);

    /* Search this item in the list. */
    item = buckets[hash & map->mask];
    record_size = map->record_size;
    while (item) {
        if (item->hash == hash && memcmp(current, item->term_set, record_size) == 0)
            return item->id;
        item = item->next;
    }

    /* Inserting a new item. */
    item = (mpm_hashitem *)malloc(map->allocation_size);
    if (!item)
        return DFA_NO_DATA;

    item->next = buckets[hash & map->mask];
    buckets[hash & map->mask] = item;
    /* Do not overwrite the first item, because that is processed currently. */
    if (map->next_unprocessed) {
        item->next_unprocessed = map->next_unprocessed->next_unprocessed;
        map->next_unprocessed->next_unprocessed = item;
    } else {
        item->next_unprocessed = NULL;
        map->next_unprocessed = item;
    }
    item->hash = hash;
    item->id = map->item_count;
    item->offset_map_size = 0;
    item->offset_map = NULL;
    memcpy(item->term_set, current, record_size);
    map->item_count++;

    if (map->item_count < map->mask || map->mask > 0x10000000)
        return item->id;

    /* Resize the hash array. */
    id = item->id;
    new_mask = (map->mask << 1) | 0x1;
    new_buckets = (mpm_hashitem **)malloc((new_mask + 1) * sizeof(mpm_hashitem *));
    if (!new_buckets)
        return DFA_NO_DATA;
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
    return id;
}

static int hashmap_sanity_check(mpm_hashmap *map)
{
    mpm_hashitem *item;
    mpm_hashitem **buckets = map->buckets;
    uint32_t mask = map->mask;
    uint32_t i;

    if (((mask + 1) & mask) != 0)
        return 1;

    for (i = mask + 1; i > 0; i--) {
        item = buckets[i - 1];
        while (item) {
            if ((item->hash & mask) != i - 1)
                return 1;
            item = item->next;
        }
    }
    return 0;
}

#if defined MPM_VERBOSE && MPM_VERBOSE
static void print_terms(mpm_hashmap *map, uint32_t *base)
{
    uint32_t bit;
    uint32_t *bit_set;
    uint32_t length;
    int32_t term;
    int32_t last_set_term;
    int value = 2, comma;

    do {
        term = 0;
        last_set_term = -1;
        bit = 0x1;
        comma = 0;
        if (value == 2) {
            bit_set = base;
            length = map->term_set_length * 32;
            printf("Active terms: <");
        } else {
            bit_set = base + map->term_set_length;
            length = map->end_state_set_length * 32;
            printf(">, Final states: <");
        }

        do {
            if (bit_set[0] & bit) {
                if (last_set_term < 0) {
                    if (comma)
                        printf(",");
                    comma = 1;
                    printf("%d", term);
                    last_set_term = term;
                }
            } else if (last_set_term >= 0) {
                if (term == last_set_term + 2) {
                    if (comma)
                        printf(",");
                    comma = 1;
                    printf("%d", term - 1);
                } else if (term > last_set_term + 2)
                    printf("-%d", term - 1);
                last_set_term = -1;
            }

            bit <<= 1;
            if (bit == 0x0) {
                bit = 0x1;
                bit_set++;
            }
            term++;
        } while (term < length);

        if (last_set_term == length - 2) {
            if (comma)
                printf(",");
            printf("%d", length - 1);
        } else if (last_set_term <= length - 3 && last_set_term >= 0) {
            if (comma)
                printf(",");
            printf("-%d", length - 1);
        }
        value--;
    } while (value);

    printf(">\n");
}

static void hashmap_stats(mpm_hashmap *map)
{
    mpm_hashitem *item;
    mpm_hashitem **buckets = map->buckets;
    uint32_t mask = map->mask;
    int count, max = 0;
    uint32_t i;

    for (i = mask + 1; i > 0; i--) {
        item = buckets[i - 1];
        count = 0;
        while (item) {
            count++;
            item = item->next;
        }
        if (count > max)
            max = count;
    }
    printf("\nHashmap statistics: items: %d buckets: %d max bucket: %d \n", map->item_count, mask + 1, max);
}
#endif

/* ----------------------------------------------------------------------- */
/*                                Main function.                           */
/* ----------------------------------------------------------------------- */

/* Accessing members of the hash map. */
#define MAP(id) (map_data.id)

int mpm_compile(mpm_re *re, int flags)
{
    mpm_hashmap map_data;
    mpm_hashmap *map = &map_data;
    mpm_re_pattern *pattern;
    mpm_hashitem *item;
    mpm_id_offset_map *id_offset, *last_id_offset;
    uint32_t *word_code;
    uint32_t *bit_set, *bit_set_end, *other_bit_set;
    uint32_t term_base, term_bits;
    uint32_t **term, **last_term;
    uint32_t *id_index, *last_id_index;
    uint8_t *compiled_pattern;
    uint8_t id_map[256];
    uint32_t id_indices[256];
    uint32_t available_chars[CHAR_SET_SIZE];
    uint32_t consumed_chars[CHAR_SET_SIZE];
    uint32_t i, j, id, offset;

    if (re->next_id == 0)
        return MPM_RE_ALREADY_COMPILED;

    if (hashmap_init(map, re->next_term_index, re->next_id - 1)) {
        hashmap_free(map);
        return MPM_NO_MEMORY;
    }

    /* Initialize data structures. */
    memset(MAP(start), 0, MAP(record_size));
    pattern = re->patterns;
    while (pattern) {
        word_code = pattern->word_code + pattern->term_range_size + 1;
        while (word_code[0] != DFA_NO_DATA) {
            DFA_SETBIT(MAP(start), word_code[0]);
            word_code++;
        }
        term = MAP(term_map) + pattern->term_range_start;
        word_code = pattern->word_code;
        last_term = term + pattern->term_range_size;
        while (term < last_term)
            *term++ = pattern->word_code + *word_code++;
        pattern = pattern->next;
    }

    memcpy(MAP(current), MAP(start), MAP(record_size));
    hashmap_insert(map);

    do {
#if defined MPM_VERBOSE && MPM_VERBOSE
        if (flags & MPM_COMPILE_VERBOSE) {
            printf("Processing %4d: ", MAP(next_unprocessed)->id);
            print_terms(map, MAP(next_unprocessed)->term_set);
        }
#endif

        /* Decoding the set of terms. */
        last_term = MAP(term_list);
        term_base = 0;
        bit_set = MAP(next_unprocessed)->term_set;
        bit_set_end = bit_set + MAP(term_set_length);
        while (bit_set < bit_set_end) {
            if (!bit_set[0]) {
                term_base += 32;
                bit_set++;
            }

            term_bits = *bit_set++;
            do {
                if (term_bits & 0x1)
                    *last_term++ = MAP(term_map)[term_base];
                term_bits >>= 1;
                term_base++;
                /* The loop stops when term_base is divisible by 32. */
            } while (term_base & 0x1f);
        }

        memset(available_chars, 0xff, CHAR_SET_SIZE * sizeof(uint32_t));
        last_id_index = id_indices;

        for (i = 0; i < 256; i++) {
            if (!CHARSET_GETBIT(available_chars, i))
                continue;

            /* Get those characters, which have the same bit set,
               and the list of reachable states. */
            memset(consumed_chars, 0xff, CHAR_SET_SIZE * sizeof(uint32_t));
            memcpy(MAP(current), MAP(start), MAP(record_size));
            term = MAP(term_list);

            if (flags & MPM_ALL_END_STATES)
                memcpy(MAP(current) + MAP(term_set_length), MAP(next_unprocessed)->term_set +
                    MAP(term_set_length), MAP(end_state_set_length) << 2);

            while (term < last_term) {
                bit_set = term[0];
                bit_set_end = bit_set + CHAR_SET_SIZE;
                other_bit_set = consumed_chars;

                if (CHARSET_GETBIT(bit_set, i)) {
                    while (bit_set < bit_set_end)
                        *other_bit_set++ &= *bit_set++;

                    word_code = term[0] + CHAR_SET_SIZE;
                    if (word_code[0] != DFA_NO_DATA)
                        DFA_SETBIT(MAP(current) + MAP(term_set_length), word_code[0]);

                    word_code ++;
                    while (word_code[0] != DFA_NO_DATA) {
                        DFA_SETBIT(MAP(current), word_code[0]);
                        word_code++;
                    }
                } else {
                    while (bit_set < bit_set_end)
                        *other_bit_set++ &= ~(*bit_set++);
                }

                term++;
            }

            bit_set = consumed_chars;
            bit_set_end = bit_set + CHAR_SET_SIZE;
            other_bit_set = available_chars;
            while (bit_set < bit_set_end) {
                /* Sanity check. */
                if (~other_bit_set[0] & bit_set[0]) {
                    hashmap_free(map);
                    return MPM_INTERNAL_ERROR;
                }
                *other_bit_set++ -= *bit_set++;
            }

            if (flags & MPM_ALL_END_STATES) {
                id = DFA_NO_DATA;
                bit_set = MAP(current) + MAP(term_set_length);
                /* This function will be more sophisticated in the future. */
                for (j = re->next_id - 1; j > 0; j--)
                    if (!DFA_GET_BIT(bit_set, j - 1)) {
                        id = hashmap_insert(map);
                        if (id == DFA_NO_DATA) {
                            hashmap_free(map);
                            return MPM_NO_MEMORY;
                        }
                        break;
                    }
            } else {
                id = hashmap_insert(map);
                if (id == DFA_NO_DATA) {
                    hashmap_free(map);
                    return MPM_NO_MEMORY;
                }
            }

#if defined MPM_VERBOSE && MPM_VERBOSE
            if (flags & MPM_COMPILE_VERBOSE) {
                printf("  For [");
                mpm_print_char_range((uint8_t *)consumed_chars);
                printf("] next state: %d\n", (int)id);
            }
#endif

            /* Search wheter the ID index is used. */
            id_index = id_indices;
            while (id_index < last_id_index) {
                if (*id_index == id) {
                    id = id_index - id_indices;
                    break;
                }
                id_index ++;
            }

            if (id_index == last_id_index)
                *last_id_index++ = id;

            id = id_index - id_indices;
            for (j = 0; j < 256; j++)
                if (CHARSET_GETBIT(consumed_chars, j))
                    id_map[j] = id;
        }

        i = (last_id_index - id_indices) * sizeof(uint32_t);
        MAP(next_unprocessed)->offset_map = (mpm_offset_map *)malloc(256 + i);
        if (!MAP(next_unprocessed)->offset_map) {
            hashmap_free(map);
            return MPM_NO_MEMORY;
        }

        memcpy(MAP(next_unprocessed)->offset_map->map, id_map, 256);
        memcpy(MAP(next_unprocessed)->offset_map->offsets, id_indices, i);
        MAP(next_unprocessed)->offset_map_size = 256 + i;

        MAP(next_unprocessed) = MAP(next_unprocessed)->next_unprocessed;
    } while (MAP(next_unprocessed));

    if (hashmap_sanity_check(map)) {
        hashmap_free(map);
        return MPM_INTERNAL_ERROR;
    }

#if defined MPM_VERBOSE && MPM_VERBOSE
    if (flags & MPM_COMPILE_VERBOSE)
        hashmap_stats(map);
#endif

    /* Free up some memory. */
    free(MAP(term_map));
    MAP(term_map) = NULL;
    free(MAP(current));
    MAP(current) = NULL;

    /* Calculating id to offset map and generate the final representation. */
    MAP(id_offset_map) = (struct mpm_id_offset_map *)malloc(MAP(item_count) * sizeof(struct mpm_id_offset_map));
    if (!MAP(id_offset_map)) {
        hashmap_free(map);
        return MPM_NO_MEMORY;
    }

    for (i = MAP(mask) + 1; i > 0; i--) {
        item = MAP(buckets)[i - 1];
        while (item) {
            MAP(id_offset_map)[item->id].item = item;
            item = item->next;
        }
    }

    id_offset = MAP(id_offset_map);
    last_id_offset = id_offset + MAP(item_count);
    offset = 0;
    while (id_offset < last_id_offset) {
        id_offset->offset = offset;
        offset += id_offset->item->offset_map_size;
        id_offset++;
    }

#if defined MPM_VERBOSE && MPM_VERBOSE
    if (flags & MPM_COMPILE_VERBOSE)
        printf("Compression save: %.2lf%% = 1 - (%d / %d)\n",
            1 - ((double)offset / (double)(MAP(item_count) * sizeof(uint32_t) * 256)),
            offset, MAP(item_count) * sizeof(uint32_t) * 256);
#endif

    compiled_pattern = (uint8_t *)malloc(offset);
    if (!compiled_pattern) {
        hashmap_free(map);
        return MPM_NO_MEMORY;
    }

    id_offset = MAP(id_offset_map);
    while (id_offset < last_id_offset) {
        id_index = id_offset->item->offset_map->offsets;
        last_id_index = id_index + ((id_offset->item->offset_map_size - 256) >> 2);
        do {
            if (id_index[0] != DFA_NO_DATA)
                id_index[0] = MAP(id_offset_map)[id_index[0]].offset;
            id_index++;
        } while (id_index < last_id_index);

        memcpy(compiled_pattern + id_offset->offset,
            id_offset->item->offset_map, id_offset->item->offset_map_size);
        id_offset++;
    }

    /* Releasing unused memory. */
    hashmap_free(map);
    re->next_id = 0;
    if (re->patterns) {
        mpm_free_patterns(re->patterns);
        re->patterns = NULL;
    }

    if (flags & MPM_ALL_END_STATES)
        re->flags |= ALL_END_STATES;
    re->compiled_pattern = compiled_pattern;

    return MPM_NO_ERROR;
}
