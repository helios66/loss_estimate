
SUBDIRS = src applications doc etc

# Automake automatically rebuilds Makefile.ins, Makefiles and the configure
# script, however runs aclocal by default without the necessary arguments
ACLOCAL_AMFLAGS = -I .

EXTRA_DIST = COPYING INSTALL applications tests \
	config/mapi.conf.dag.entry \
	config/mapi.conf.ipfixflib.entry

dist-hook:
	rm -rf `find $(distdir)/applications -name .svn`
	rm -rf `find $(distdir)/tests -name .svn`
