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
#include "mpm_pcre.h"
#include "mpm_pcre_internal.h"

/* ----------------------------------------------------------------------- */
/*                                Main function.                           */
/* ----------------------------------------------------------------------- */

static pcre_uchar * get_bracket_end(pcre_uchar *ptr)
{
    do {
        ptr += GET(ptr, 1);
    } while (*ptr == OP_ALT);

    return ptr + 1 + LINK_SIZE;
}

static mpm_uint32 get_bracket_size(pcre_uchar *real_byte_code, pcre_uchar *instrumented_byte_code)
{
    pcre_uchar *from = real_byte_code;

    real_byte_code = get_bracket_end(real_byte_code);

    if (instrumented_byte_code[0] != OP_CALLOUT)
        return real_byte_code - from;

    instrumented_byte_code += 2 + 2 * LINK_SIZE;
    if (instrumented_byte_code[0] != OP_BRA)
        return real_byte_code - from;
    instrumented_byte_code = get_bracket_end(instrumented_byte_code);

    while (instrumented_byte_code[0] == OP_BRA && real_byte_code[0] == OP_BRA) {
        real_byte_code = get_bracket_end(real_byte_code);
        instrumented_byte_code = get_bracket_end(instrumented_byte_code);
    }

    if (instrumented_byte_code[0] == OP_SBRA && real_byte_code[0] == OP_SBRA)
        real_byte_code = get_bracket_end(real_byte_code);
    else if ((instrumented_byte_code[0] == OP_BRAZERO || instrumented_byte_code[0] == OP_BRAMINZERO)
            && (instrumented_byte_code[1] == OP_BRA || instrumented_byte_code[1] == OP_SBRA)
            && (instrumented_byte_code[0] == real_byte_code[0] && instrumented_byte_code[1] == real_byte_code[1]))
        real_byte_code = get_bracket_end(real_byte_code + 1);

    return real_byte_code - from;
}

static int mpm_private_get_byte_code(mpm_byte_code **byte_code, mpm_char8 *pattern, mpm_uint32 flags)
{
    int options = PCRE_NEWLINE_CRLF | PCRE_BSR_ANYCRLF | PCRE_NO_AUTO_CAPTURE;
    REAL_PCRE *real_pcre_re;
    REAL_PCRE *instrumented_pcre_re;
    const char *errptr;
    int error, callout, special, length;
    mpm_char8 *fixed = NULL;
    mpm_char8 *fixed_ptr;
    mpm_char8 *pattern_ptr;
    pcre_uchar *real_byte_code;
    pcre_uchar *instrumented_byte_code;
    pcre_uchar *byte_code_end;
    pcre_uchar *byte_code_start;
    mpm_uint32 fixed_size;
    mpm_uint32 pattern_length;
    mpm_uint32 byte_code_length;
    mpm_byte_code_data *byte_code_data_ptr;

    *byte_code = NULL;
    fixed_size = GET_FIXED_SIZE(flags);
    if (fixed_size > 0) {
        if (flags & (MPM_ADD_MULTILINE | MPM_ADD_DOTALL | MPM_ADD_EXTENDED))
            return MPM_INVALID_PATTERN;

        fixed = (mpm_char8 *)malloc(fixed_size * 4 + 1);
        if (!fixed)
            return MPM_NO_MEMORY;

        /* Convert the pattern to a \x sequence. */
        fixed_ptr = fixed;
        pattern_ptr = pattern;
        do {
            *fixed_ptr++ = '\\';
            *fixed_ptr++ = 'x';
            error = *pattern_ptr >> 4;
            *fixed_ptr++ = (error < 10) ? (error + '0') : (error - 10 + 'a');
            error = *pattern_ptr & 0xf;
            *fixed_ptr++ = (error < 10) ? (error + '0') : (error - 10 + 'a');
            pattern_ptr++;
        } while (--fixed_size);
        *fixed_ptr = '\0';
        fixed_size = GET_FIXED_SIZE(flags);
    }

    if (flags & MPM_ADD_CASELESS)
        options |= PCRE_CASELESS;
    if (flags & MPM_ADD_MULTILINE)
        options |= PCRE_MULTILINE;
    if (flags & MPM_ADD_ANCHORED)
        options |= PCRE_ANCHORED;
    if (flags & MPM_ADD_DOTALL)
        options |= PCRE_DOTALL;
    if (flags & MPM_ADD_EXTENDED)
        options |= PCRE_EXTENDED;

    pattern_ptr = fixed ? fixed : pattern;
    real_pcre_re = (REAL_PCRE *)mpm_pcre_compile((char*)pattern_ptr, options, &errptr, &error, NULL);
    instrumented_pcre_re = (REAL_PCRE *)mpm_pcre_compile((char*)pattern_ptr, options | PCRE_AUTO_CALLOUT, &errptr, &error, NULL);
    if (fixed)
        free(fixed);

    if (!real_pcre_re || !instrumented_pcre_re) {
        if (real_pcre_re)
            mpm_pcre_free((pcre *)real_pcre_re);
        if (instrumented_pcre_re)
            mpm_pcre_free((pcre *)instrumented_pcre_re);
        return MPM_UNSUPPORTED_PATTERN;
    }

    real_byte_code = (pcre_uchar *)real_pcre_re + real_pcre_re->name_table_offset
        + real_pcre_re->name_count * real_pcre_re->name_entry_size;
    instrumented_byte_code = (pcre_uchar *)instrumented_pcre_re + instrumented_pcre_re->name_table_offset
        + instrumented_pcre_re->name_count * instrumented_pcre_re->name_entry_size;

    /* Some sanity checks. */
    if (real_byte_code[0] != OP_BRA || instrumented_byte_code[0] != OP_BRA) {
        error = MPM_UNSUPPORTED_PATTERN;
        goto leave;
    }

    byte_code_length = get_bracket_end(real_byte_code) - real_byte_code;
    if (real_byte_code[byte_code_length] != OP_END) {
        error = MPM_UNSUPPORTED_PATTERN;
        goto leave;
    }

    byte_code_end = real_byte_code + byte_code_length;

    *byte_code = (mpm_byte_code*)malloc(sizeof(mpm_byte_code) + (sizeof(mpm_byte_code_data) * (byte_code_length - 1)) + byte_code_length);
    if (!*byte_code) {
        mpm_pcre_free((pcre *)real_pcre_re);
        mpm_pcre_free((pcre *)instrumented_pcre_re);
        return MPM_NO_MEMORY;
    }

    (*byte_code)->byte_code_length = byte_code_length;
    (*byte_code)->pattern = pattern;
    (*byte_code)->flags = flags;
    byte_code_data_ptr = (*byte_code)->byte_code_data;
    pattern_ptr = (mpm_uint8 *)(byte_code_data_ptr + byte_code_length);
    (*byte_code)->byte_code = pattern_ptr;
    memcpy(pattern_ptr, real_byte_code, byte_code_length);
    memset(byte_code_data_ptr, 0, sizeof(mpm_byte_code_data) * byte_code_length);

    byte_code_data_ptr->byte_code_length = byte_code_length;
    byte_code_data_ptr->pattern_offset = 0;
    byte_code_data_ptr->pattern_length = fixed_size ? fixed_size : strlen((char *)pattern);

    if (real_byte_code[GET(real_byte_code, 1)] == OP_ALT)
        real_byte_code = byte_code_end;
    else
        real_byte_code += 1 + LINK_SIZE;
    instrumented_byte_code += 1 + LINK_SIZE;
    byte_code_data_ptr += 1 + LINK_SIZE;

    while (real_byte_code < byte_code_end) {
        length = PRIV(OP_lengths)[*real_byte_code];
        callout = 1;
        special = 0;

        switch (*real_byte_code) {
        case OP_NOT_DIGIT:
        case OP_DIGIT:
        case OP_NOT_WHITESPACE:
        case OP_WHITESPACE:
        case OP_NOT_WORDCHAR:
        case OP_WORDCHAR:
        case OP_ANY:
        case OP_ALLANY:
        case OP_NOT_HSPACE:
        case OP_HSPACE:
        case OP_NOT_VSPACE:
        case OP_VSPACE:
        case OP_CHAR:
        case OP_CHARI:
        case OP_NOT:
        case OP_NOTI:

        case OP_EXACT:
        case OP_EXACTI:
        case OP_NOTEXACT:
        case OP_NOTEXACTI:
        case OP_TYPEEXACT:
            if (instrumented_byte_code[0] == OP_CALLOUT
                    && instrumented_byte_code[length + 2 + 2 * LINK_SIZE] >= OP_STAR
                    && instrumented_byte_code[length + 2 + 2 * LINK_SIZE] <= OP_TYPEMINUPTO) {
                length += PRIV(OP_lengths)[real_byte_code[length]];
            }
            byte_code_data_ptr->byte_code_length = length;
            break;

        case OP_CIRC:
        case OP_CIRCM:
        case OP_DOLL:
        case OP_DOLLM:

        case OP_STAR:
        case OP_MINSTAR:
        case OP_PLUS:
        case OP_MINPLUS:
        case OP_QUERY:
        case OP_MINQUERY:
        case OP_UPTO:
        case OP_MINUPTO:

        case OP_STARI:
        case OP_MINSTARI:
        case OP_PLUSI:
        case OP_MINPLUSI:
        case OP_QUERYI:
        case OP_MINQUERYI:
        case OP_UPTOI:
        case OP_MINUPTOI:

        case OP_NOTSTAR:
        case OP_NOTMINSTAR:
        case OP_NOTPLUS:
        case OP_NOTMINPLUS:
        case OP_NOTQUERY:
        case OP_NOTMINQUERY:
        case OP_NOTUPTO:
        case OP_NOTMINUPTO:

        case OP_NOTSTARI:
        case OP_NOTMINSTARI:
        case OP_NOTPLUSI:
        case OP_NOTMINPLUSI:
        case OP_NOTQUERYI:
        case OP_NOTMINQUERYI:
        case OP_NOTUPTOI:
        case OP_NOTMINUPTOI:

        case OP_TYPESTAR:
        case OP_TYPEMINSTAR:
        case OP_TYPEPLUS:
        case OP_TYPEMINPLUS:
        case OP_TYPEQUERY:
        case OP_TYPEMINQUERY:
        case OP_TYPEUPTO:
        case OP_TYPEMINUPTO:
            byte_code_data_ptr->byte_code_length = length;
            break;

        case OP_CLASS:
        case OP_NCLASS:
            if (real_byte_code[length] >= OP_CRSTAR && real_byte_code[length] <= OP_CRMINRANGE)
                length += PRIV(OP_lengths)[real_byte_code[length]];
            byte_code_data_ptr->byte_code_length = length;
            break;

        case OP_BRAZERO:
        case OP_BRAMINZERO:
            length = PRIV(OP_lengths)[*(real_byte_code + 1)];
            if (real_byte_code[1] != OP_BRA && real_byte_code[1] != OP_SBRA) {
                error = MPM_UNSUPPORTED_PATTERN;
                goto leave;
            }
            byte_code_data_ptr->byte_code_length = get_bracket_end(real_byte_code + 1) - real_byte_code;
            special = 2;
            break;

        case OP_BRA:
            byte_code_data_ptr->byte_code_length = get_bracket_size(real_byte_code, instrumented_byte_code);
            special = 1;
            break;

        case OP_SBRA:
            byte_code_data_ptr->byte_code_length = get_bracket_end(real_byte_code) - real_byte_code;
            special = 1;
            break;

        case OP_KET:
            special = 3;
            callout = 0;
            break;

        case OP_KETRMAX:
        case OP_KETRMIN:
            callout = 0;
            break;

        case OP_ALT:
            error = MPM_INTERNAL_ERROR;
            goto leave;

        default:
            error = MPM_UNSUPPORTED_PATTERN;
            goto leave;
        }

        if ((instrumented_byte_code[0] != OP_CALLOUT || instrumented_byte_code[1] != 0xff)) {
            error = MPM_INTERNAL_ERROR;
            goto leave;
        }

        pattern_length = GET(instrumented_byte_code, 2 + LINK_SIZE);
        if (callout) {
            byte_code_data_ptr->pattern_offset = GET(instrumented_byte_code, 2);
            byte_code_data_ptr->pattern_length = pattern_length;
            if (fixed_size) {
                /* Divide by four. */
                byte_code_data_ptr->pattern_offset >>= 2;
                byte_code_data_ptr->pattern_length >>= 2;
            }
        }
        instrumented_byte_code += 2 + 2 * LINK_SIZE;

        if ((real_byte_code[0] != instrumented_byte_code[0]) || (callout && !pattern_length) || (!callout && pattern_length)) {
            error = MPM_INTERNAL_ERROR;
            goto leave;
        }

        if (special == 2) {
            real_byte_code += 1;
            instrumented_byte_code += 1;
            byte_code_data_ptr += 1;
        }

        if ((special == 1 && real_byte_code[GET(real_byte_code, 1)] == OP_ALT) || special == 2) {
            byte_code_start = real_byte_code;
            real_byte_code = get_bracket_end(real_byte_code) - (1 + LINK_SIZE);
            instrumented_byte_code = get_bracket_end(instrumented_byte_code) - (1 + LINK_SIZE + 2 + 2 * LINK_SIZE);
            byte_code_data_ptr += real_byte_code - byte_code_start;
        } else {
            real_byte_code += length;
            instrumented_byte_code += length;
            byte_code_data_ptr += length;
        }

        if (special == 3) {
            byte_code_start = real_byte_code;
            while (instrumented_byte_code[0] == OP_BRA && real_byte_code[0] == OP_BRA) {
                real_byte_code = get_bracket_end(real_byte_code);
                instrumented_byte_code = get_bracket_end(instrumented_byte_code);
            }

            if (instrumented_byte_code[0] == OP_SBRA && real_byte_code[0] == OP_SBRA) {
                real_byte_code = get_bracket_end(real_byte_code);
                instrumented_byte_code = get_bracket_end(instrumented_byte_code);
            } else if ((instrumented_byte_code[0] == OP_BRAZERO || instrumented_byte_code[0] == OP_BRAMINZERO)
                    && (instrumented_byte_code[1] == OP_BRA || instrumented_byte_code[1] == OP_SBRA)
                    && (instrumented_byte_code[0] == real_byte_code[0] && instrumented_byte_code[1] == real_byte_code[1])) {
                real_byte_code = get_bracket_end(real_byte_code + 1);
                instrumented_byte_code = get_bracket_end(instrumented_byte_code + 1);
            }
            byte_code_data_ptr += real_byte_code - byte_code_start;
        }
    }

    mpm_pcre_free((pcre *)real_pcre_re);
    mpm_pcre_free((pcre *)instrumented_pcre_re);
    return MPM_NO_ERROR;

leave:
    mpm_pcre_free((pcre *)real_pcre_re);
    mpm_pcre_free((pcre *)instrumented_pcre_re);
    if (*byte_code)
        free(*byte_code);
    *byte_code = NULL;
    return error;
}
