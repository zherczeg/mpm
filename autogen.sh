#!/bin/sh

rm -rf autom4te.cache Makefile.in aclocal.m4

aclocal --force -I m4
libtoolize -c -f
autoconf -f -W all,no-obsolete
autoheader -f -W all
automake -a -c -f -W all

rm -rf autom4te.cache
