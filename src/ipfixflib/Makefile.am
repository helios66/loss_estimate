AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/../lib -I$(srcdir)/../drivers -I$(srcdir)/../common -D_GNU_SOURCE -D_THREAD_SAFE

# install ipfixflib into $(prefix)/share/mapi/
libdir = $(pkgdatadir)

# mapi function libraries are dynamically loadable modules (but not standalone
# libraries for users)

lib_LTLIBRARIES = ipfixflib.la
ipfixflib_la_LDFLAGS = -module

ipfixflib_la_LIBADD = \
../common/libcbuf.la \
../common/libfhelp.la \
../common/libmapiipc.la \
../common/libflist.la \
../common/libmsearch.la \
../common/libdebug.la \
../common/libparseconf.la \
../common/libacsmx2.la \
 -lm -lz -lpcap

ipfixflib_la_SOURCES = \
engine.c engine.h\
ifp-priv.h \
ipfixlib.c \
ipfixprobe.c \
md5.c md5.h \
npctrl.c npctrl.h \
npctxt.h \
npktproc.c npktproc.h \
nprobe_bucket.h \
nprobe.c nprobe.h \
nprobe-priv.h \
services.c services.h \
util.c util.h \
mpegts.c mpegts.h

# these headers will be installed in $prefix/include/mapi
pkginclude_HEADERS = ipfixlib.h

EXTRA_DIST = COPYING etter.passive.os.fp README-nprobe
