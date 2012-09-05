AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/../lib -I$(srcdir)/../drivers -I$(srcdir)/../common @NAPATECHINC@ -D_NT_OS_TYPE=_NT_OS_TYPE_LINUX -D_GNU_SOURCE -D_THREAD_SAFE
libdir = $(pkgdatadir)

# napatechflib
# mapi function libraries are dynamically loadable modules (but not standalone
# libraries for users)
lib_LTLIBRARIES = napatechflib.la
napatechflib_la_LDFLAGS = -module
napatechflib_la_LIBADD = \
../common/libflist.la \
../common/libmsearch.la \
../common/libfhelp.la \
../common/libparseconf.la \
../common/libprintfstring.la \
../common/libdebug.la \
../common/libmapiipc.la @NAPATECHLIB@
napatechflib_la_SOURCES = napatechflib.c interface.c bpffilter.c
