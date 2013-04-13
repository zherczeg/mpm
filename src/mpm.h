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
 * \brief The public header of of the Multi Pattern Matcher (MPM) library.
 *
 * \author Zoltan Herczeg <zherczeg@inf.u-szeged.hu>
 */

#ifndef mpm_h
#define mpm_h

/* Types required by MPM: */

  /*! An unsigned byte character representation (0-255). */
typedef unsigned char mpm_char8;
  /*! Length of the subject in mpm_exec. */
typedef unsigned long mpm_size;
  /*! 8 bit long unsigned integer for bit sets. */
typedef unsigned char mpm_uint8;
  /*! 16 bit long unsigned integer for pattern lists. */
typedef unsigned short mpm_uint16;
  /*! 32 bit long unsigned integer for flags and result bit sets. */
typedef unsigned int mpm_uint32;

/*! Private representation of a regular expression set. */
struct mpm_re_internal;
/*! Public representation of a regular expression set. */
typedef struct mpm_re_internal mpm_re;

/* MPM error codes. */

/*! No error. */
#define MPM_NO_ERROR                    0
/*! Out of memory occured. */
#define MPM_NO_MEMORY                   1
/*! Internal error (should never happen). */
#define MPM_INTERNAL_ERROR              2
/*! Pattern cannot be compiled by PCRE. */
#define MPM_INVALID_PATTERN             3
/*! Pattern is not supported by the MPM library. */
#define MPM_UNSUPPORTED_PATTERN         4
/*! Pattern matches an empty string (matches to any input). */
#define MPM_EMPTY_PATTERN               5
/*! Invalid or unsupported arguments. */
#define MPM_INVALID_ARGS                6
/*! Cannot add more regular expressions (max 32). */
#define MPM_PATTERN_LIMIT               7
/*! Pattern is not suitable for a DFA based engine. */
#define MPM_TOO_LOW_RATING              8
/*! Pattern has been already compiled by mpm_compile. */
#define MPM_RE_ALREADY_COMPILED         9
/*! Pattern must be compiled first by mpm_compile. */
#define MPM_RE_IS_NOT_COMPILED          10
/*! Number of allowed states is reached. */
#define MPM_STATE_MACHINE_LIMIT         11
/*! No such pattern (invalid index argument). */
#define MPM_NO_SUCH_PATTERN             12

char *mpm_error_to_string(int error_code);

/*! \fn char *mpm_error_to_string(int error_code)
 *  \brief Converts the error_code to human readable string.
 *  \param error_code an error code returned by any mpm function.
 *  \return String representation of the error code.
 */

mpm_re * mpm_create(void);

/*! \fn mpm_re * mpm_create(void)
 *  \brief Create an empty set of regular expressions.
 *  \return a newly created set of regular expressions.
 */

void mpm_free(mpm_re *re);

/*! \fn void mpm_free(mpm_re *re)
 *  \brief Free the set of regular expressions (regardless it is compiled or not).
 *  \param re set of regular expressions created by mpm_create.
 */

/* Flags for mpm_add: */

/*! Caseless match (see mpm_add). */
#define MPM_ADD_CASELESS                0x001
/*! Multiline match (see mpm_add). */
#define MPM_ADD_MULTILINE               0x002
/*! Anchored match (see mpm_add). */
#define MPM_ADD_ANCHORED                0x004
/*! Dot matches to all characters (see mpm_add). */
#define MPM_ADD_DOTALL                  0x008
/*! Extended regular expression (see mpm_add). */
#define MPM_ADD_EXTENDED                0x010
/*! Returns with MPM_TOO_LOW_RATING if the pattern is not
    suitable for matching with a DFA based engine (see mpm_add). */
#define MPM_ADD_TEST_RATING             0x020
/* This flag is ignored if MPM_VERBOSE is undefined. */
/*! Verbose the operations of mpm_add. */
#define MPM_ADD_VERBOSE                 0x040
/*! \brief Add a fixed string (all characters are treated
 *         as normal characters). Can only be combined with
 *         MPM_ADD_CASELESS flag.
 *  \param size Size of the string (maximum 64K). */
#define MPM_ADD_FIXED(size)             (((size) & 0xffff) << 12)

int mpm_add(mpm_re *re, mpm_char8 *pattern, mpm_uint32 flags);

/*! \fn int mpm_add(mpm_re *re, mpm_char8 *pattern, mpm_uint32 flags)
 *  \brief Adds a new pattern to the set of regular expressions. The maximum number of patterns is 32.
 *  \param re set of regular expressions created by mpm_create.
 *  \param pattern a new pattern.
 *  \param flags flags started by MPM_ADD_ prefix.
 *  \return MPM_NO_ERROR on success.
 */

/* Compile the pattern. */

  /*  The maximum number of states is reduced to 1/4 . */
#define MPM_COMPILE_SMALL_MACHINE       0x001
  /*  This flag is ignored if MPM_VERBOSE is undefined. */
  /*! Verbose the operations of mpm_compile. */
#define MPM_COMPILE_VERBOSE             0x002
  /*  This flag is ignored if MPM_VERBOSE is undefined. */
  /*! Display some statistics (e.g: memory consumption) about the compiled pattern. */
#define MPM_COMPILE_VERBOSE_STATS       0x004

int mpm_compile(mpm_re *re, mpm_size *consumed_memory, mpm_uint32 flags);

/*! \fn int mpm_compile(mpm_re *re, mpm_uint32 flags)
 *  \brief Compiles the pattern set into a single DFA representation.
 *  \param re set of regular expressions created by mpm_create.
 *  \param consumed_memory if this argument is non-NULL, it contains the memory
 *                         consumption of the machine when MPM_NO_ERROR is returned.
 *                         Otherwise its value is undefined.
 *  \param flags flags started by MPM_COMPILE_ prefix.
 *  \return MPM_NO_ERROR on success.
 */

/* Execute the pattern. */

int mpm_exec(mpm_re *re, mpm_char8 *subject, mpm_size length, mpm_size offset, mpm_uint32 *result);

/*! \fn int mpm_exec(mpm_re *re, mpm_char8 *subject, mpm_size length, mpm_size offset, mpm_uint32 *result)
 *  \brief Matches the compiled regular expression to the subject string.
 *  \param re set of regular expressions compiled by mpm_compile.
 *  \param subject points to the start of the subject buffer.
 *  \param length length of the subject buffer.
 *  \param offset starting position of the matching inside the subject buffer.
 *  \param result points to a 32 bit long buffer where the result of the match
 *         is stored. The first bit of the buffer represents the first pattern
 *         added by mpm_add, and it is set, if that pattern matches. It is cleared
 *         otherwise. The second bit represents the second pattern, and so on.
 *  \return MPM_NO_ERROR on success.
 */

int mpm_exec4(mpm_re **re, mpm_char8 *subject, mpm_size length, mpm_size offset, mpm_uint32 *results);

/*! \fn int mpm_exec4(mpm_re **re, mpm_char8 *subject, mpm_size length, mpm_size offset, mpm_uint32 *results)
 *  \brief Matches four compiled regular expressions to the same subject string (mpm_exec matches only one).
 *  \param re four sets of regular expressions compiled by mpm_compile.
 *  \param subject points to the start of the subject buffer.
 *  \param length length of the subject buffer.
 *  \param offset starting position of the matching inside the subject buffer.
 *  \param result points to four, 32 bit long buffer. The purpose of these buffers
 *                are described in mpm_exec. The first buffer belongs to re[0],
 *                the second to re[1], and so on.
 *  \return MPM_NO_ERROR on success.
 */

/* Utility functions. */

mpm_re * mpm_dummy_re(void);

/* ! \fn mpm_re * mpm_dummy_re(void)
 *  \brief Returns a dummy regular expression, which never matches anything.
 *         Can be passed as a valid re for mpm_exec or mpm_exec4.
 */

/*! Copy source instead of merge it. The source will not be deleted. */
#define MPM_COMBINE_COPY                0x001

int mpm_combine(mpm_re **destination_re, mpm_re *source_re, mpm_uint32 flags);

/*! \fn int mpm_combine(mpm_re *destination_re, mpm_re *source_re)
 *  \brief The patterns stored by source_re are added at the end of
 *         *destination_re. If successful, source_re is freed. Otherwise
 *         both set of regular expressions are left unchanged.
 *  \param destination_re *destination_re points to a set of regular expressions
 *                        created by mpm_create (the set must not be compiled by
 *                        mpm_compile) or NULL to create a new one.
 *  \param source_re set of regular expressions created by mpm_create
 *                   (the set must not be compiled by mpm_compile).
 *  \param flags flags started by MPM_COMBINE_ prefix.
 *  \return MPM_NO_ERROR on success.
 */

int mpm_distance(mpm_re *re1, mpm_size index1, mpm_re *re2, mpm_size index2);

/*! \fn int mpm_distance(mpm_re *re1, int index1, mpm_re *re2, int index2)
 *  \brief Rates the distance between two patterns.
 *         The re1 and re2 arguments can be the same.
 *  \param re1 set of regular expressions created by mpm_create
 *             (the set must not be compiled by mpm_compile).
 *  \param index1 the index of the pattern in re1. The first pattern added by
 *                mpm_add has index 0, the second has index 1, and so on.
 *  \param re2 set of regular expressions created by mpm_create
 *             (the set must not be compiled by mpm_compile).
 *  \param index2 the index of the pattern in re1. The first pattern added by
 *                mpm_add has index 0, the second has index 1, and so on.
 *  \return if the return value is <= 0, it contains the distance. The distance
 *          computed by a heuristc algorithm, and not an absolute value. It
 *          ranges between 0 and -128, lower is worse. Otherwise an error
 *          code is returned (e.g: MPM_NO_MEMORY).
 */

int mpm_rating(mpm_re *re, mpm_size index);

/*! \fn int mpm_rating(mpm_re *re, mpm_size index)
 *  \brief Rating a pattern. The return value tells whether the pattern
 *         can be efficiently handled by the mpm matcher.
 *  \param re set of regular expressions created by mpm_create
 *            (the set must not be compiled by mpm_compile).
 *  \param index the index of the pattern in re1. The first pattern added by
 *               mpm_add has index 0, the second has index 1, and so on.
 *  \return if the return value is between -16 and -1, it contains the rating.
 *          Closer to 0 is better, so a pattern with the rate of -1 is likely
 *          efficiently handled by the mpm library. On the contrary, a pattern
 *          with -16 rate should be matched by another engine. Otherwise
 *          an error code is returned (e.g: MPM_NO_MEMORY).
 */

/*! Structure used only by mpm_clustering. */
typedef struct mpm_cluster_item {
    mpm_uint32 group_id;   /*!< The group id. Starting from 0, and increased by 1 for each
                                new group. This field is an output only argument. */
    mpm_re *re;            /*!< This parameter should contain a single pattern. */
    void *data;            /*!< User pointer, which keeps its value after the reordering. */
} mpm_cluster_item;

  /*  This flag is ignored if MPM_VERBOSE is undefined. */
  /*! Verbose the operations of mpm_clustering. */
#define MPM_CLUSTERING_VERBOSE          0x001

int mpm_clustering(mpm_cluster_item *items, mpm_size no_items, mpm_uint32 flags);

/*! \fn int mpm_clustering(mpm_cluster_item *items, mpm_size no_items, mpm_uint32 flags)
 *  \brief Groups similar patterns into one set.
 *  \param items list of patterns. Items are fully reordered if the function is successful,
 *               so this is an output argument as well.
 *  \param no_items length of the items argument.
 *  \param flags flags started by MPM_CLUSTERING_ prefix.
 *  \return MPM_NO_ERROR on success.
 */

/* Rule lists management. */

/*! Marks the start of a new rule for mpm_compile_rules. */
#define MPM_RULE_NEW                    0x100

/*! Structure used only by mpm_create_rule_set. */
typedef struct mpm_rule_pattern {
    mpm_char8 *pattern;    /*!< Pattern string. */
    mpm_uint32 flags;      /*!< Any combination of MPM_ADD_ and MPM_RULE_ flags. */
} mpm_rule_pattern;

  /*  This flag is ignored if MPM_VERBOSE is undefined. */
  /*! Verbose the operations of mpm_compile_rules. */
#define MPM_COMPILE_RULES_VERBOSE       0x001
  /*  This flag is ignored if MPM_VERBOSE is undefined. */
  /*! Display some statistics (e.g: memory consumption) about the compiled patterns. */
#define MPM_COMPILE_RULES_VERBOSE_STATS 0x002

/*! Private representation of a regular expression set. */
struct mpm_rule_list_internal;
/*! Public representation of a regular expression set. */
typedef struct mpm_rule_list_internal mpm_rule_list;

int mpm_compile_rules(mpm_rule_pattern *rules, mpm_size no_rule_patterns, mpm_rule_list **result_rule_list, mpm_size *consumed_memory, mpm_uint32 flags);

/*! \fn int mpm_compile_rules(mpm_rule_pattern *rules, mpm_size no_rule_patterns, mpm_rule_list **result_rule_list, mpm_uint32 flags);
 *  \brief Compiles a rule set to an internal representation
 *  \param rules an array of mpm_rule_pattern items.
 *  \param no_rule_patterns number of rules.
 *  \param result_rule_list output argument, which contains the compiled rule set.
 *  \param consumed_memory if this argument is non-NULL, it contains the memory
 *                         consumption of the machine when MPM_NO_ERROR is returned.
 *                         Otherwise its value is undefined.
 *  \param flags flags started by MPM_COMPILE_RULES_ prefix.
 *  \return MPM_NO_ERROR on success.
 */

void mpm_rule_list_free(mpm_rule_list *rule_list);

/*! \fn void mpm_rule_list_free(mpm_rule_list *rule_list)
 *  \brief Free the compiled rule set.
 *  \param rule_list a list returned by mpm_compile_rules
 */

int mpm_exec_list(mpm_rule_list *rule_list, mpm_char8 *subject, mpm_size length, mpm_size offset, mpm_uint32 *result);

/*! \fn int mpm_exec_list(mpm_rule_list *rule_list, mpm_char8 *subject, mpm_size length, mpm_size offset, mpm_uint32 *result);
 *  \brief Matches the compiled rule list to the subject string.
 *  \param rule_list a list returned by mpm_compile_rules
 *  \param subject points to the start of the subject buffer.
 *  \param length length of the subject buffer.
 *  \param offset starting position of the matching inside the subject buffer.
 *  \param result points to a 32 bit long buffer where the result of the match
 *         is stored. The first bit of the buffer represents the first rule
 *         and it is set, if that rule matches. It is cleared otherwise. The
 *         second bit represents the second rule, and so on.
 *  \return MPM_NO_ERROR on success.
 */

#endif // mpm_h
