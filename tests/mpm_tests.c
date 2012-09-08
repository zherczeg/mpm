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

#include <stdlib.h>
#include <stdio.h>
#include "mpm.h"

static int test_failed = 0;

static void test_mpm_add(mpm_re *re, char *pattern, int flags)
{
    int error_code = mpm_add(re, pattern, flags);
    if (error_code != MPM_NO_ERROR) {
        printf("WARNING: mpm_add is failed: %s\n\n", mpm_error_to_string(error_code));
        test_failed = 1;
    }
}

static void verbose_mpm_add(void)
{
    mpm_re *re = mpm_create();
    if (!re) {
        test_failed = 1;
        return;
    }

    test_mpm_add(re, "m\\x00\\xff.", MPM_ADD_VERBOSE);
    test_mpm_add(re, "[^c][^\\x00][^\\x01][^\\xfe][^\\xff].", MPM_ADD_DOTALL | MPM_ADD_VERBOSE);
    test_mpm_add(re, "ab[^c][^e]\\xff", MPM_ADD_CASELESS | MPM_ADD_VERBOSE);
    test_mpm_add(re, " [a-z] [\\x00-\\x05x-\\xff] (?i)[c-fMX] ", MPM_ADD_EXTENDED | MPM_ADD_VERBOSE);
    test_mpm_add(re, "(ab|cd(mn|op)+|ef(gh)?)*", MPM_ADD_VERBOSE);

    test_mpm_add(re, "\\d\\D\\w\\W\\s\\S\\h\\H\\v\\V", MPM_ADD_CASELESS | MPM_ADD_VERBOSE);

    test_mpm_add(re, "#a+?#b*#c??#d{3,6}#e{0,3}?#f{2,}#", MPM_ADD_VERBOSE);
    test_mpm_add(re, "#a+#b*?#c?#d{3,6}?#e{0,3}#f{2,}?#", MPM_ADD_CASELESS | MPM_ADD_VERBOSE);
    test_mpm_add(re, "#[^a]+?#[^b]*#[^c]??#[^d]{3,6}#[^e]{0,3}?#[^f]{2,}#", MPM_ADD_VERBOSE);
    test_mpm_add(re, "#[^a]+#[^b]*?#[^c]?#[^d]{3,6}?#[^e]{0,3}#[^f]{2,}?#", MPM_ADD_CASELESS | MPM_ADD_VERBOSE);
    test_mpm_add(re, "#\\s+?#\\w*#\\d??#\\S{3,6}#.{0,3}?#\\h{2,}#", MPM_ADD_CASELESS | MPM_ADD_VERBOSE);
    test_mpm_add(re, "#[a-z]+?#[a-z]*#[a-z]??#[a-z]{3,6}#[a-z]{0,3}?#[a-z]{2,}#", MPM_ADD_VERBOSE);

    test_mpm_add(re, "", MPM_ADD_VERBOSE);
    test_mpm_add(re, "(ab)?", MPM_ADD_VERBOSE);
    test_mpm_add(re, "(a?b)+", MPM_ADD_VERBOSE);
    test_mpm_add(re, "(a|b*b|d+?)x", MPM_ADD_VERBOSE);
    test_mpm_add(re, "(a|(bc?)|d(ee|f)*)+", MPM_ADD_VERBOSE);

    mpm_compile(re);

    mpm_free(re);
}

int main()
{
    printf("Running MPM (multi-pattern matcher) tests\n\n");
    verbose_mpm_add();
    return test_failed;
}
