AM_CPPFLAGS = -I$(top_srcdir)/src/lib

if BINARY_APPMON
bin_PROGRAMS =  appmon appform.cgi
endif

appmon_LDADD = -L$(top_srcdir)/src/lib -lrrd -lmapi
appmon_SOURCES = appmon.c \
	util.c \
	anon_prefix_preserving.c \
	pidfile.c

appform_cgi_LDADD = -L$(top_srcdir)/src/lib -lcgic
appform_cgi_SOURCES = appform.c \
	util.c
