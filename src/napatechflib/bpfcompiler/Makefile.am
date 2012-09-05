
# set the include path found by configure
INCLUDES=-I.. -I../..

# the library search path.
SUBDIRS = pcap

# install extraflib into $(prefix)/share/mapi/
libdir = $(pkgdatadir)

libbpfcompiler_la_LDFLAGS = -avoid-version -no-undefined
lib_LTLIBRARIES = libbpfcompiler.la
libbpfcompiler_la_LIBADD = pcap/libpcap.la
libbpfcompiler_la_SOURCES = bpf_compile.c bpf_compile.h bpf_grammar.c \
		bpf_grammar.h bpf.h bpf_lexical.c bpf_node.c bpf_node.h bpf_pcap.h bpf_transform.c \
		bpf_dagdsm.c utils.c utils.h bpf_dagdsm.h

noinst_PROGRAMS = bpftest
bin_PROGRAMS = bpf2dagdsm

bpftest_LDADD = libbpfcompiler.la
bpftest_SOURCES = bpftest.c

bpf2dagdsm_LDADD = libbpfcompiler.la
bpf2dagdsm_SOURCES = bpf2dagdsm.c

# bison should become something like $(BISON)
bpf_grammar.c bpf_grammar.h: bpf_grammar.y
	bison -d -obpf_grammar.c bpf_grammar.y

# flex should become something like $(FLEX)
bpf_lexical.c: bpf_lexical.l
	flex -obpf_lexical.c bpf_lexical.l

DISTCLEANFILES = bpf_grammar.c bpf_grammar.h bpf_lexical.c
