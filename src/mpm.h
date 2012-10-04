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

#ifndef mpm_h
#define mpm_h

/* Internal representation of a multipattern. */
struct mpm_re_internal;
typedef struct mpm_re_internal mpm_re;

/* MPM error codes. */
#define MPM_NO_ERROR                    0
#define MPM_NO_MEMORY                   1
#define MPM_INTERNAL_ERROR              2
#define MPM_INVALID_PATTERN             3
#define MPM_EMPTY_PATTERN               4
#define MPM_UNSUPPORTED_PATTERN         5
#define MPM_RE_ALREADY_COMPILED         6
#define MPM_RE_IS_NOT_COMPILED          7
#define MPM_BIG_STATE_MACHINE           8

char *mpm_error_to_string(int error_code);

/* Create a new pattern. */
mpm_re * mpm_create(void);
void mpm_free(mpm_re *re);

/* Add a new pattern to the pattern list. */
#define MPM_ADD_CASELESS                0x001
#define MPM_ADD_MULTILINE               0x002
#define MPM_ADD_ANCHORED                0x004
#define MPM_ADD_DOTALL                  0x008
#define MPM_ADD_EXTENDED                0x010
/* This flag is ignored if MPM_VERBOSE is undefined. */
#define MPM_ADD_VERBOSE                 0x020
/* Fixed strings does not support all the flags above.
   The maximum size of a fixed string is 64K. */
#define MPM_ADD_FIXED(size)             (((size) & 0xffff) << 8)

int mpm_add(mpm_re *re, char *pattern, int flags);

/* Compile the pattern. */
  /* Generate all end states. Faster, but more memory is consumed. */
#define MPM_COMPILE_VERBOSE             0x001
#define MPM_COMPILE_VERBOSE_STATS       0x002

int mpm_compile(mpm_re *re, int flags);

/* Match the pattern. Returns non-zero if successful. */
int mpm_exec(mpm_re *re, char *subject, int length, unsigned int *result);
int mpm_exec3(mpm_re **re, char *subject, int length, unsigned int *result);
int mpm_exec4(mpm_re **re, char *subject, int length, unsigned int *result);
int mpm_exec6(mpm_re **re, char *subject, int length, unsigned int *result);
int mpm_exec8(mpm_re **re, char *subject, int length, unsigned int *result);

#endif // mpm_h
