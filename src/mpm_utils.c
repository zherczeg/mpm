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

mpm_re * mpm_create(void)
{
    mpm_re *re = (mpm_re *)malloc(sizeof(mpm_re));
    if (!re)
        return NULL;

    re->next_id = 1;
    re->next_term_index = 0;
    re->patterns = NULL;

    return re;
}

static void free_patterns(mpm_re_pattern *pattern)
{
    mpm_re_pattern *next;
    while (pattern) {
        next = pattern->next;
        free(pattern);
        pattern = next;
    }
}

void mpm_free(mpm_re *re)
{
    if (re->patterns)
        free_patterns(re->patterns);
    free(re);
}

char *mpm_error_to_string(int error_code)
{
    switch (error_code) {
    case MPM_NO_ERROR:
        return "No error";
    case MPM_NO_MEMORY:
        return "Out of memory occured";
    case MPM_INTERNAL_ERROR:
        return "Internal error (should never happen)";
    case MPM_INVALID_PATTERN:
        return "Pattern cannot be compiled by PCRE";
    case MPM_EMPTY_PATTERN:
        return "Pattern matches an empty string";
    case MPM_UNSUPPORTED_PATTERN:
        return "Pattern is not supported by MPM";
    case MPM_RE_ALREADY_COMPILED:
        return "Patter has been already compiled by mpm_compile";
    default:
        return "Unknown error";
    }
}
