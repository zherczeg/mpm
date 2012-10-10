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
/*! Cannot add more regular expressions (max 32). */
#define MPM_PATTERN_LIMIT               6
/*! Pattern has been already compiled by mpm_compile. */
#define MPM_RE_ALREADY_COMPILED         7
/*! Pattern must be compiled first by mpm_compile. */
#define MPM_RE_IS_NOT_COMPILED          8
/*! Number of allowed states is reached. */
#define MPM_STATE_MACHINE_LIMIT         9

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
/* This flag is ignored if MPM_VERBOSE is undefined. */
/*! Verbose the operations of mpm_add. */
#define MPM_ADD_VERBOSE                 0x020
/*! \brief Add a fixed string (all characters are treated
 *         as normal characters). Can only be combined with
 *         MPM_ADD_CASELESS flag.
 *  \param size Size of the string (maximum 64K). */
#define MPM_ADD_FIXED(size)             (((size) & 0xffff) << 8)

int mpm_add(mpm_re *re, mpm_char8 *pattern, mpm_uint32 flags);

/*! \fn int mpm_add(mpm_re *re, mpm_char8 *pattern, mpm_uint32 flags)
 *  \brief Adds a new pattern to the set of regular expressions. The maximum number of patterns is 32.
 *  \param re set of regular expressions created by mpm_create.
 *  \param pattern a new pattern.
 *  \param flags flags started by MPM_ADD_ prefix.
 *  \return MPM_NO_ERROR on success.
 */

/* Compile the pattern. */

  /*  This flag is ignored if MPM_VERBOSE is undefined. */
  /*! Verbose the operations of mpm_compile. */
#define MPM_COMPILE_VERBOSE             0x001
  /*  This flag is ignored if MPM_VERBOSE is undefined. */
  /*! Display some statistics (e.g: memory consumption) about the compiled pattern. */
#define MPM_COMPILE_VERBOSE_STATS       0x002

int mpm_compile(mpm_re *re, mpm_uint32 flags);

/*! \fn int mpm_compile(mpm_re *re, mpm_uint32 flags)
 *  \brief Combines the pattern set into a single DFA representation.
 *  \param re set of regular expressions created by mpm_create.
 *  \param flags flags started by MPM_COMPILE_ prefix.
 *  \return MPM_NO_ERROR on success.
 */

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

#endif // mpm_h
