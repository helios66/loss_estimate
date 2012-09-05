CC = gcc
CFLAGS = -g -O2 -W -Wall
LDFLAGS = -lmapi

SOURCES=$(wildcard *.c)
TARGETS=$(SOURCES:.c=)


all: $(TARGETS)

% : %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:	
	rm -rf $(TARGETS)
