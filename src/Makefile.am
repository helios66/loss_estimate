AM_CPPFLAGS = -I$(srcdir)/lib -I$(srcdir)/common -I$(srcdir)/drivers -D_GNU_SOURCE -D_THREAD_SAFE

if BINARY_TRACKFLIB
BUILD_trackflib = trackflib
endif
if BINARY_RULERFLIB
BUILD_rulerflib = rulerflib
endif
if BINARY_IPFIXFLIB
BUILD_ipfixflib = ipfixflib
endif
if BINARY_ANONFLIB
BUILD_anonflib = anonflib
endif
if BINARY_DAGFLIB
BUILD_dagflib = dagflib
endif
if BINARY_NAPATECHFLIB
BUILD_napatechflib = napatechflib
endif
if BINARY_EXTRAFLIB
BUILD_extraflib = extraflib
endif

# common must be built first
SUBDIRS = common lib drivers stdflib \
$(BUILD_trackflib) \
$(BUILD_rulerflib) \
$(BUILD_ipfixflib) \
$(BUILD_anonflib) \
$(BUILD_dagflib) \
$(BUILD_napatechflib) \
$(BUILD_extraflib)
#DIST_SUBDIRS = 

if BINARY_DIMAPI
BUILD_mapicommd = mapicommd
endif

sbin_PROGRAMS = mapid $(BUILD_mapicommd)

mapid_LDADD = \
common/libflist.la \
common/libmapiipc.la \
lib/libmapi_local.la \
common/libparseconf.la \
common/libprintfstring.la -lpthread -ldl \
common/libdebug.la \
common/liblog.la
mapid_SOURCES = mapid.c mapid.h mapidevices.h debug.h pidfile.c pidfile.h

if BINARY_DIMAPI
mapicommd_LDADD = \
common/libmapiipc.la \
common/libmapilibhandler.la \
common/libfhelp.la \
common/libflist.la \
common/libparseconf.la \
common/libprintfstring.la \
lib/libmapi.la \
lib/libmapi_remote.la \
common/libdebug.la \
common/liblog.la
mapicommd_SOURCES = mapicommd.c
endif


EXTRA_DIST = errors.mapi vod

dist-hook:
	rm -rf `find $(distdir)/combo6flib -name .svn`
	rm -rf `find $(distdir)/vod -name .svn`

# if installing as root, create a mapi user group
install-exec-hook:
	@if test `whoami` = root; then \
		if $(GROUPADD) -f ${MAPI_GROUP}; then\
			echo "Created user group '${MAPI_GROUP}'"; \
		fi \
	fi
