#ifndef __TRACKER_LOG__
	#define __TRACKER_LOG__

//#define __TRACKFLIB_LOGGING__ 

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


void write_to_log(char *proto, char *string, int protocol, struct in_addr  sip, uint16_t  sp, struct in_addr dip, uint16_t dp, unsigned char *packet, unsigned int len);

#endif 
