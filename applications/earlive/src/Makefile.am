if BINARY_STRIDE
STRIDE = stride
STRIDE_LIB = stride/libstride.la
endif

SUBDIRS = ear $(STRIDE)

bin_PROGRAMS = earmonitor

earmonitor_LDADD = \
ear/libear.la $(STRIDE_LIB)

earmonitor_SOURCES = \
hex.c hex.h \
options.c options.h \
report.c report.h \
main.c

