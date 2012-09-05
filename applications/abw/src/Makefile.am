## Process this file with automake to produce Makefile.in

bin_PROGRAMS = abw abw_info

GCC_WARNINGS = -Wall -W -Wfloat-equal -Wundef -Wshadow -Wcast-qual	\
	-Wsign-compare -Wstrict-prototypes -Wmissing-prototypes	\
	-Wmissing-declarations -Wredundant-decls -Wnested-externs

SUBDIRS = 

#ABW_VAR_DIR = /var/lib/abw

install-exec-local:
	@chmod 755 $(top_srcdir)/scripts/*.sh
	@cp $(top_srcdir)/scripts/*.sh $(prefix)/bin

install-data-local:
	@mkdir -p $(prefix)/etc
	@mkdir -p $(ABW_VAR_DIR)/.ssh
	@mkdir -p $(ABW_VAR_DIR)/rrd
	@mkdir -p $(ABW_VAR_DIR)/graph
	@mkdir -p $(ABW_VAR_DIR)/log

	@if test ! -f $(prefix)/etc/abw.conf ; then \
		cp -u $(top_srcdir)/etc/abw.conf	$(prefix)/etc ; \
	else :; fi

	@if test $(CREATE_GROUP) -gt 0 ; then \
		$(ADDGROUP) $(GROUP) ; \
	else :; fi

	@if test $(CREATE_USER) -gt 0 ; then \
		$(ADDUSER) $(DEF_HOME) $(ABW_VAR_DIR) $(DEF_GROUP) $(GROUP) $(DEF_PASSWD) $(DEF_COMMENT) "abw application" $(USER) ; \
	else :; fi

	@chown $(USER):$(GROUP) $(ABW_VAR_DIR)/graph
	@chown $(USER):$(GROUP) $(ABW_VAR_DIR)/.ssh

######################################################################
# abw

abw_CFLAGS = $(GCC_WARNINGS) -g -O2

abw_CPPFLAGS = \
	-DPROGNAME=\"abw\"	\
	$(GLIB_CFLAGS)	\
	$(MAPI_CFLAGS) \
	-DDIMAPI \
	-DPREFIX=\"$(prefix)\" \
	-DABW_VAR_DIR=\"$(ABW_VAR_DIR)\"

abw_LDADD = \
	$(GLIB_LIBS) \
	$(MAPI_LIBS) \
	-lreadline -lm

abw_SOURCES = \
	abw.c \
	abw_common.c abw_common.h \
	abw_time.c abw_time.h \
	abw_conf.c abw_conf.h \
	abw_rrd.c abw_rrd.h

######################################################################
# abw_info

abw_info_CFLAGS = $(GCC_WARNINGS) -g -O2

abw_info_CPPFLAGS = \
	-DPROGNAME=\"abw_info\"	\
	$(GLIB_CFLAGS)	\
	$(MAPI_CFLAGS) \
	-DDIMAPI \
	-DPREFIX=\"$(prefix)\" \
	-DABW_VAR_DIR=\"$(ABW_VAR_DIR)\"

abw_info_LDADD = \
	$(GLIB_LIBS) \
	$(MAPI_LIBS) \
	-lreadline -lm

abw_info_SOURCES = \
	abw_info.c abw_info.h \
	abw_conf.c abw_conf.h \
	abw_common.c abw_common.h \
	abw_rrd.c abw_rrd.h
