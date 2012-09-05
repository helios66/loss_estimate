CC = gcc
RM = rm -f
CFLAGS = -g -O2 -Wall -I..
BINS = mapiinfo

.PHONY: all clean

all: $(BINS)

mapiinfo.o: mapiinfo.c
	$(CC) $(CFLAGS) -c $<

mapiinfo: mapiinfo.o 
	$(CC) $(CFLAGS) -lmapi mapiinfo.o -o mapiinfo

clean:
	$(RM) *.o $(BINS)
