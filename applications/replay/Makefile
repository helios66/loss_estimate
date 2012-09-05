CC=gcc
CFLAGS=-Wall -O2
LIBS=-lpcap
INSTALL=install -c

all:tsh2eth

install:all
	$(INSTALL) -m 755 tsh2eth /usr/local/bin/
	$(INSTALL) -m 644 template.pcap /etc/
	$(INSTALL) -m 755 replayer.sh /usr/local/bin/

tsh2eth: tsh2eth.c
	$(CC) $(CFLAGS) -o $@ $<  $(LIBS)

clean:
	rm -f tsh2eth
