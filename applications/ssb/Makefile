CC = gcc
RM = rm -f
CFLAGS = -g -O2 -Wall -I..
BINS = ssb

.PHONY: all clean

all: $(BINS)

ssb.o: ssb.c
	$(CC) $(CFLAGS) -c $<

ssb: ssb.o
	$(CC) $(CFLAGS) ssb.o -o ssb -lpthread -lmapi

clean:
	$(RM) *.o $(BINS)
