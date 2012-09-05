AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/../lib -I$(srcdir)/../drivers -I$(srcdir)/../common -D_GNU_SOURCE -D_THREAD_SAFE
libdir = $(pkgdatadir)

# rulerflib
# mapi function libraries are dynamically loadable modules (but not standalone
# libraries for users)
lib_LTLIBRARIES = rulerflib.la
check_PROGRAMS = testcompiler example
rulerflib_la_LDFLAGS = -module
rulerflib_la_SOURCES = rulerflib.c helper-functions.h
rulerflib_la_LIBADD = \
  ../common/libflist.la \
  ../common/libmapiipc.la \
  ../common/libfhelp.la

testcompiler_SOURCES = testcompiler.c helper-functions.h
testcompiler_LDADD = -ldl

example_LDADD = ../lib/libmapi.la

EXTRA_DIST = 00README.txt

TESTS = runtest
