#SUBDIRS = libnids
AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/../lib -I$(srcdir)/../common -I$(srcdir)/../drivers @PCAPINC@ @NIDSINC@ @PCREINC@ -D_GNU_SOURCE -D_THREAD_SAFE

# install extraflib into $(prefix)/share/mapi/
libdir = $(pkgdatadir)

lib_LTLIBRARIES = extraflib.la
extraflib_la_LDFLAGS = -module 
extraflib_la_LIBADD = \
../common/libflist.la \
../common/libfhelp.la \
../common/libdebug.la \
../common/libmapiipc.la @PCAPLIB@ @PCRELIB@ -lm \
@NIDSLIB@ 
extraflib_la_SOURCES = \
cooking.c cooking.h \
extraflib.c \
pcapio.h \
protocols.h \
regexp.c \
topx.c \
exprflow.c\
anonymizeip.c\
rijndael.c rijndael.h\
panonymizer.c panonymizer.h

pkginclude_HEADERS = topx.h expiredflowshash.h protocols.h
