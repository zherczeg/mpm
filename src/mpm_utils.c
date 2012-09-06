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
        return "Pattern matches to empty string";
    case MPM_UNSUPPORTED_PATTERN:
        return "Pattern is not supported by MPM";
    case MPM_RE_ALREADY_COMPILED:
        return "Patter has been already compiled by mpm_compile";
    default:
        return "Unknown error";
    }
}
