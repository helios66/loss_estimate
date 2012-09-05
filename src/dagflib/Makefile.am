AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/../lib -I$(srcdir)/../drivers -I$(srcdir)/../common @DAGINC@ -D_GNU_SOURCE -D_THREAD_SAFE
libdir = $(pkgdatadir)

# Helplib for BPF_FILTER
SUBDIRS = bpfcompiler

# dagflib
# mapi function libraries are dynamically loadable modules (but not standalone
# libraries for users)
lib_LTLIBRARIES = dagflib.la
dagflib_la_LDFLAGS = -module
dagflib_la_LIBADD = \
../common/libflist.la \
../common/libmsearch.la \
../common/libfhelp.la \
../common/libparseconf.la \
../common/libprintfstring.la \
../common/libdebug.la \
bpfcompiler/libbpfcompiler.la \
../common/libmapiipc.la @DAGLIB@
#../../../trunk/src/bpfcompiler/libbpfcompiler.la

dagflib_la_SOURCES = dagflib.c interface.c to_erf.c bpffilter.c
