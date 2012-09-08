ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libmpm.la

include_HEADERS = \
  mpm.h

libmpm_la_SOURCES = \
  mpm_internal.h \
  mpm_add.c \
  mpm_compile.c \
  mpm_utils.c \
  mpm_pcre/mpm_pcre.h \
  mpm_pcre/mpm_pcre_internal.h \
  mpm_pcre/mpm_pcre_chartables.c \
  mpm_pcre/mpm_pcre_compile.c \
  mpm_pcre/mpm_pcre_globals.c \
  mpm_pcre/mpm_pcre_newline.c \
  mpm_pcre/mpm_pcre_tables.c

libmpm_la_CFLAGS = -I$(srcdir)/mpm_pcre
