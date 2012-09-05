#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <string.h>
#include <signal.h>

#include "mapiipc.h"
#include "debug.h"
#include "mapidflib.h"

// TODO: clean up headers*!

// Helper functions for function arguments retrieval
int getargint(mapiFunctArg **pos){
	int i;
	i = *((int *)(*pos));
	//	printf("getint: %d\n", i);
	(*pos) += sizeof(int);
	return i;
}

char getargchar(mapiFunctArg **pos){
	char c;
	c = *((char *)(*pos));
	//printf("getchar: %c\n", c);
	(*pos) += sizeof(char);
	return c;
}

unsigned long long getargulonglong(mapiFunctArg **pos){
	unsigned long long l;
	l = *((unsigned long long *)(*pos));
	//printf("getulonglong: %lld\n", l);
	(*pos) += sizeof(unsigned long long);
	return l;
}

char * getargstr(mapiFunctArg **pos){
	char *s;
	s = (char*)*pos;
	//printf("getstr: %s\n", s);
	(*pos) += strlen(s)+1;
	return s;
}

void addarg(mapiFunctArg **pos, void *arg, int type)
// Helper function for mapi_apply_function()
// pos: current position in message's argument buffer.
// arg: argument to copy into buffer
// type: argument type
{
  switch(type){
    case INT:
      memcpy(*pos, arg, sizeof(int));
      //printf("add_arg: %d\n", *((int *)(*pos)));
      (*pos) += sizeof(int);
      break;
    case CHAR:
      memcpy(*pos, arg, sizeof(char));
      //printf("add_arg: %d\n", *((char *)(*pos)));
      (*pos) += sizeof(char);
      break;
    case UNSIGNED_LONG_LONG:
      memcpy(*pos, arg, sizeof(unsigned long long));
      //printf("add_arg: %llu\n", *((unsigned long long *)(*pos)));
      (*pos) += sizeof(unsigned long long);
      break;
    case STRING:
      memcpy(*pos, arg, strlen((char *)arg)+1);
      //printf("add_arg: %s\n", (char *)(*pos));
      (*pos) += strlen((char *)arg)+1;
      break;
    default:
      break;
  }
}
