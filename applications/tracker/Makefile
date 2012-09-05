CC = gcc
RM = rm -f
CFLAGS = -g -O2 -Wall -I..
BINS = tracker

.PHONY:	all clean

TRACKER_DEPS=fasttrack.o ftptraffic.o winmx.o mail.o protos.o http.o ether_protos.o dns.o msn.o radio.o netbios.o shells.o more.o torent.o eigrp.o gprs.o kerberos.o sunrpc.o ssdp.o ucp.o who.o xdmcp.o

all: $(BINS)

util.o:	util.c
	$(CC) $(CFLAGS) -c $<

fasttrack.o:	fasttrack.c
	$(CC) $(CFLAGS) -c $<

ftptraffic.o:	ftptraffic.c
	$(CC) $(CFLAGS) -c $<
	
winmx.o:	winmx.c
	$(CC) $(CFLAGS) -c $<

tracker.o:	tracker.c
	$(CC) $(CFLAGS) -c $<

protos.o:	protos.c
	$(CC) $(CFLAGS) -c $<

ether_protos.o:	ether_protos.c
	$(CC) $(CFLAGS) -c $<

mail.o:	mail.c 
	$(CC) $(CFLAGS) -c $<

http.o:	http.c
	$(CC) $(CFLAGS) -c $<

dns.o:	dns.c
	$(CC) $(CFLAGS) -c $<

msn.o: msn.c
	$(CC) $(CFLAGS) -c $<

radio.o: radio.c
	$(CC) $(CFLAGS) -c $<

netbios.o:	netbios.c
	$(CC) $(CFLAGS) -c $<

shells.o:	shells.c
	$(CC) $(CFLAGS) -c $<

more.o: more.c
	$(CC) $(CFLAGS) -c $<

torent.o:	torent.c
	$(CC) $(CFLAGS) -c $<

eigrp.o:	eigrp.c
	$(CC) $(CFLAGS) -c $<

gprs.o:	gprs.c
	$(CC) $(CFLAGS) -c $<

kerberos.o:	kerberos.c
	$(CC) $(CFLAGS) -c $<

sunrpc.o:	sunrpc.c
	$(CC) $(CFLAGS) -c $<

ssdp.o:	ssdp.c
	$(CC) $(CFLAGS) -c $<

ucp.o:	ucp.c
	$(CC) $(CFLAGS) -c $<

who.o:	who.c
	$(CC) $(CFLAGS) -c $<

xdmcp.o:	xdmcp.c
	$(CC) $(CFLAGS) -c $<

tracker:	tracker.o util.o $(TRACKER_DEPS)
	$(CC) $(CFLAGS) -o tracker tracker.o util.o $(TRACKER_DEPS) -lmapi -lpcap -lpthread

clean:	
	$(RM) *.o $(BINS) *.bin
