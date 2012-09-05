AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/../lib -I$(srcdir)/../drivers -I$(srcdir)/../common -D_GNU_SOURCE -D_THREAD_SAFE
libdir = $(pkgdatadir)

# trackflib
# mapi function libraries are dynamically loadable modules (but not standalone
# libraries for users)
lib_LTLIBRARIES = trackflib.la
trackflib_la_LDFLAGS = -module
trackflib_la_LIBADD = \
../common/libflist.la \
../common/libmsearch.la \
../common/libdebug.la \
../common/libacsmx2.la
trackflib_la_SOURCES = \
dc.c \
edonkey.c edonkey.h \
gnutella.c \
ipoverip.c \
irc.c \
log.c log.h \
torrent.c \
skype.c \
trackflib.c trackflib.h \
trackftp.c trackftp.h \
gridftp.c \
web.c \
mapi.c
