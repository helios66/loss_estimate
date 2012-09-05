AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/../lib -I$(srcdir)/../common -I$(srcdir)/../drivers @PCAPINC@ -D_GNU_SOURCE -D_THREAD_SAFE

# install mapidstdflib into $(prefix)/share/mapi/
libdir = $(pkgdatadir)

# stdflib
# mapi function libraries are dynamically loadable modules (but not standalone
# libraries for users)
lib_LTLIBRARIES = stdflib.la
stdflib_la_LDFLAGS = -module 
stdflib_la_LIBADD = \
../common/libflist.la \
../common/libfhelp.la \
../common/libmapiipc.la \
../common/libdebug.la \
../common/libmsearch.la @PCAPLIB@ -lm
stdflib_la_SOURCES = stdflib.c \
binop.c binop.h \
bpffilter.c \
burst.c  burst.h \
bucket.c \
bytecounter.c \
dist.c \
fifo.c fifo.h \
gap.c \
hash.c \
hashsamp.c \
pktcounter.c \
pktinfo.c \
res2file.c \
sample.c \
startstop.c \
stats.c \
strsearch.c \
sync.c \
threshold.c threshold.h \
tobuffer_all.c \
to_tcpdump.c

# these headers will be installd in $prefix/include/mapi
pkginclude_HEADERS = bucket.h burst.h dist.h hashsamp.h pktinfo.h res2file.h sample.h stats.h
