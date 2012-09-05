## Process this file with automake to produce Makefile.in
AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/../lib -I$(srcdir)/../drivers @SSLINC@ -D_GNU_SOURCE -D_THREAD_SAFE

noinst_LTLIBRARIES = libflist.la libfhelp.la libmapiipc.la libparseconf.la libprintfstring.la libmapilibhandler.la libmsearch.la libacsmx2.la libcbuf.la libdebug.la liblog.la
libflist_la_SOURCES = flist.c flist.h
libflist_la_DEPENDENCIES = mapi_errors.h
libfhelp_la_SOURCES = fhelp.c fhelp.h
libmapiipc_la_SOURCES = mapiipc.c mapiipc.h
libmapiipc_la_LIBADD = @SSLLIB@
libparseconf_la_SOURCES = parseconf.c parseconf.h
libprintfstring_la_SOURCES = printfstring.c printfstring.h
libmapilibhandler_la_SOURCES = mapilibhandler.c mapilibhandler.h
libmsearch_la_SOURCES = mstring.c mstring.h
libacsmx2_la_SOURCES = acsmx2.c acsmx2.h
libcbuf_la_SOURCES = cbuf.c cbuf.h kernel_memory.h
libdebug_la_SOURCES = debug.c debug.h
liblog_la_SOURCES = log.c log.h

noinst_HEADERS = mapidflib.h mapi_errors.h

mapi_errors.h: $(srcdir)/../errors.mapi
	echo -e "#ifndef _MAPI_ERRORS_H_ \n#define _MAPI_ERRORS_H_\n" > mapi_errors.h	
	echo -e "typedef struct errstrct{ \nint err_no;  \nchar *desc; 	\n} errorstruct;\n" >> mapi_errors.h
	cat $(srcdir)/../errors.mapi|grep "^#" >> mapi_errors.h
	echo -e "#endif\n" >> mapi_errors.h

clean-local:
	-rm -f mapi_errors.h
