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

/* Internal representation of a multipattern. */
struct internal_mpm_re;
typedef struct internal_mpm_re mpm_re;

/* MPM error codes. */
#define MPM_NO_ERROR		0
#define MPM_NO_MEMORY		1

/* Create a new pattern. */
mpm_re * mpm_create(void);

/* Add a new pattern to the pattern list. */
int mpm_add(mpm_re *re, char *pattern, int flags);

/* Compile the pattern. */
int mpm_compile(mpm_re *re);

