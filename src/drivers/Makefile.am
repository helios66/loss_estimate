AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/../lib -I$(srcdir)/../common @PCAPINC@ @DAGINC@ @NAPATECHINC@ -D_NT_OS_TYPE=_NT_OS_TYPE_LINUX -D_GNU_SOURCE -D_THREAD_SAFE
libdir = $(pkgdatadir)

if DRIVER_DAG
BUILD_dagdrv = mapidagdrv.la
endif

if DRIVER_NAPATECH
BUILD_napatechdrv = mapinapatechdrv.la
endif

if DRIVER_NAPATECH_X
BUILD_napatechdrv_x = mapinapatechdrv_x.la
endif

if DRIVER_ENP2611
BUILD_enp2611drv = mapienp2611drv.la
endif

lib_LTLIBRARIES = mapinicdrv.la mapivindrv.la $(BUILD_dagdrv) $(BUILD_enp2611drv) $(BUILD_napatechdrv_x) $(BUILD_napatechdrv)

# mapi device drivers are dynamically loadable modules (but not standalone
# libraries for users)
mapinicdrv_la_LDFLAGS = -module
mapinicdrv_la_LIBADD = \
../common/libflist.la \
../common/libmapiipc.la \
../common/libparseconf.la \
../common/libprintfstring.la \
../common/libdebug.la \
../common/libmapilibhandler.la @PCAPLIB@ -lrt 
mapinicdrv_la_SOURCES = mapinicdrv.c mapidlib.c mapidlib.h mapidrv.h

mapivindrv_la_LDFLAGS = -module
mapivindrv_la_LIBADD = \
../common/libflist.la \
../common/libmapiipc.la \
../common/libparseconf.la \
../common/libprintfstring.la \
../common/libdebug.la \
../common/libmapilibhandler.la @PCAPLIB@ -lrt 
mapivindrv_la_SOURCES = mapivindrv.c mapidlib.c mapidlib.h mapidrv.h


if DRIVER_DAG
mapidagdrv_la_LDFLAGS = -module
mapidagdrv_la_LIBADD = \
../common/libflist.la \
../common/libmapiipc.la \
../common/libparseconf.la \
../common/libprintfstring.la \
../common/libmapilibhandler.la \
../common/libdebug.la \
@DAGLIB@ -lrt
mapidagdrv_la_SOURCES = mapidagdrv.c mapidlib.c mapidlib.h mapidrv.h
endif

if DRIVER_NAPATECH_X
mapinapatechdrv_x_la_LDFLAGS = -module
mapinapatechdrv_x_la_LIBADD = \
../common/libflist.la \
../common/libmapiipc.la \
../common/libparseconf.la \
../common/libprintfstring.la \
../common/libmapilibhandler.la \
../common/libdebug.la \
@NAPATECHLIB@
mapinapatechdrv_x_la_SOURCES = mapinapatechdrv_x.c mapidlib.c mapidlib.h mapidrv.h
endif

if DRIVER_NAPATECH
mapinapatechdrv_la_LDFLAGS = -module
mapinapatechdrv_la_LIBADD = \
../common/libflist.la \
../common/libmapiipc.la \
../common/libparseconf.la \
../common/libprintfstring.la \
../common/libmapilibhandler.la \
../common/libdebug.la \
-lrt @NAPATECHLIB@ 
mapinapatechdrv_la_SOURCES = mapinapatechdrv.c mapidlib.c mapidlib.h mapidrv.h
endif

if DRIVER_ENP2611
mapienp2611drv_la_LDFLAGS = -module
mapienp2611drv_la_LIBADD = \
../common/libflist.la \
../common/libmapiipc.la \
../common/libparseconf.la \
../common/libprintfstring.la \
../common/libdebug.la \
../common/libmapilibhandler.la -lrt
mapienp2611drv_la_SOURCES = mapienp2611drv.c mapidlib.c mapidlib.h mapidrv.h
endif
