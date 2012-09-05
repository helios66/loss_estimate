AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/../common -I$(srcdir)/../drivers -D_GNU_SOURCE -D_THREAD_SAFE

if LIB_DIMAPI
BUILD_libmapi_remote = libmapi_remote.la
endif

lib_LTLIBRARIES = libmapi.la libmapi_local.la $(BUILD_libmapi_remote)
#libmapi_la_DEPENDENCIES = ../common/libflist.la
libmapi_la_LDFLAGS = -no-undefined -avoid-version
libmapi_la_LIBADD = \
../common/libflist.la \
../common/libfhelp.la \
../common/libmapiipc.la \
../common/libparseconf.la \
../common/libprintfstring.la \
../common/libmapilibhandler.la -lpthread -ldl \
../common/libdebug.la
libmapi_la_SOURCES = mapi.c mapi_errors.c

libmapi_local_la_LDFLAGS = -module
libmapi_local_la_LIBADD = \
libmapi.la \
../common/libflist.la \
../common/libmapiipc.la
libmapi_local_la_SOURCES = mapi_local.c mapi_local.h mapi_flowdrv.h

if LIB_DIMAPI
libmapi_remote_la_LDFLAGS = -module
libmapi_remote_la_LIBADD = \
libmapi.la \
../common/libflist.la \
../common/libparseconf.la \
../common/libmapiipc.la
libmapi_remote_la_SOURCES = mapi_remote.c mapi_remote.h mapi_flowdrv.h
endif

include_HEADERS = mapi.h

mapi_errors.c: $(srcdir)/../errors.mapi
	echo -e "#include \"mapi_errors.h\"\n" > mapi_errors.c
	echo -e "const errorstruct Errors[] = {" >> mapi_errors.c
	cat ../errors.mapi|grep -v "#"| awk -F= '{print "{" $$1 "," $$2 "},"}' >> mapi_errors.c
	echo -e "{0,0}\n};" >> mapi_errors.c

clean-local:
	-rm -f mapi_errors.c
