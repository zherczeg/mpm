ACLOCAL_AMFLAGS = -I m4

noinst_PROGRAMS = mpm_tests
TESTS = mpm_tests

mpm_tests_SOURCES = \
  mpm_tests.c

mpm_tests_CFLAGS = -I$(top_srcdir)/src
mpm_tests_LDADD = $(top_builddir)/src/libmpm.la
