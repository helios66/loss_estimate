AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/../lib -I$(srcdir)/../drivers -I$(srcdir)/../common @PCREINC@ -D_GNU_SOURCE -D_THREAD_SAFE
libdir = $(pkgdatadir)

# anonflib
# mapi function libraries are dynamically loadable modules (but not standalone
# libraries for users)
lib_LTLIBRARIES = anonflib.la
anonflib_la_LDFLAGS = -module
anonflib_la_LIBADD = \
../common/libflist.la \
../common/libmapiipc.la \
../common/libdebug.la \
../common/libfhelp.la -lm @PCRELIB@
anonflib_la_SOURCES = \
aes.c aes.h \
anon_checksums.c \
anonflib.c \
anon_prefix_preserving.c anon_prefix_preserving.h \
anon_print_packet.c \
anon_snort_decode.c \
anonymization_functions.c anonymization_functions.h \
anonymize.c \
crc32.c crc32.h \
decoders.c \
des.c des.h \
md5.c md5.h \
names.c names.h \
prefix_preserving_map.c prefix_preserving_map.h \
print_packet.c \
sha1.c sha1.h \
sha256.c sha256.h \
uncook.c

pkginclude_HEADERS = anonymization.h anon_snort_decode.h
