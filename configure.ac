dnl A library for multi-pattern matching

m4_define(mpm_major, [0])
m4_define(mpm_minor, [1])

AC_PREREQ(2.57)
AC_INIT(mpm, mpm_major.mpm_minor, zherczeg@inf.u-szeged.hu, mpm)
AC_CONFIG_MACRO_DIR([m4])
# m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_HEADERS(config.h)

AM_INIT_AUTOMAKE
AC_PROG_CC
AM_PROG_CC_C_O
LT_INIT

AC_CONFIG_FILES(
	Makefile
	src/Makefile
	tests/Makefile
)

AC_OUTPUT
