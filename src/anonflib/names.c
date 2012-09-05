#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include "names.h"

char *anonnames[] = {
"DUMMY",
"IP",
"TCP",
"UDP",
"ICMP",
"HTTP",
"FTP",
"UNCHANGED", 
"MAP",
"MAP_DISTRIBUTION",
"STRIP",
"RANDOM",
"HASHED",
"PATTERN_FILL",
"ZERO",
"REPLACE",
"PREFIX_PRESERVING",
"PREFIX_PRESERVING_MAP",
"CHECKSUM_ADJUST",
"FILENAME_RANDOM",
"REGEXP",
"PAD_WITH_ZERO",
"STRIP_REST",
"SHA",
"MD5",
"CRC32",
"SHA_2",
"TRIPLEDES",
"AES",
"DES",
"BASE_FIELD_DEFS",
"PAYLOAD", //common to all protocols
"CHECKSUM",
"SRC_IP",
"DST_IP",
"TTL",
"TOS",
"ID",
"VERSION",
"OPTIONS",
"PACKET_LENGTH",
"IP_PROTO",
"IHL",
"FRAGMENT_OFFSET",
"SRC_PORT",
"DST_PORT",
"SEQUENCE_NUMBER",
"OFFSET_AND_RESERVED",
"ACK_NUMBER",
"FLAGS",
"URGENT_POINTER",
"WINDOW",
"TCP_OPTIONS",
"UDP_DATAGRAM_LENGTH",
"TYPE",
"CODE",
"BASE_HTTP_DEFS", //the number of first definition for HTTP
"HTTP_VERSION",
"METHOD",
"URI",
"USER_AGENT",
"ACCEPT",
"ACCEPT_CHARSET",
"ACCEPT_ENCODING",
"ACCEPT_LANGUAGE",
"ACCEPT_RANGES",
"AGE",
"ALLOW",
"AUTHORIZATION",
"CACHE_CONTROL", 
"CONNECTION_TYPE",  
"CONTENT_TYPE",
"CONTENT_LENGTH",
"CONTENT_LOCATION",
"CONTENT_MD5",
"CONTENT_RANGE",
"COOKIE",
"ETAG",
"EXPECT", 
"EXPIRES",
"FROM",
"HOST",
"IF_MATCH",
"IF_MODIFIED_SINCE",
"IF_NONE_MATCH",
"IF_RANGE",
"IF_UNMODIFIED_SINCE",
"LAST_MODIFIED",
"MAX_FORWRDS",
"PRAGMA",
"PROXY_AUTHENTICATE",
"PROXY_AUTHORIZATION",
"RANGE",
"REFERRER",
"RETRY_AFTER",
"SET_COOKIE",
"SERVER",
"TE",
"TRAILER",
"TRANSFER_ENCODING",
"UPGRADE",
"VIA",
"WARNING",
"WWW_AUTHENTICATE",
"X_POWERED_BY",
"RESPONSE_CODE",
"RESP_CODE_DESCR",
"VARY",
"DATE",
"CONTENT_ENCODING",
"KEEP_ALIVE",
"LOCATION",
"CONTENT_LANGUAGE",
"DERIVED_FROM",
"ALLOWED",
"MIME_VERSION",
"TITLE",
"REFRESH",
"HTTP_PAYLOAD", //for internal use
"END_HTTP_DEFS",
"BASE_FTP_DEFS",
"USER", //has arg
"PASS", //has arg
"ACCT", //has arg
"FTP_TYPE", //has arg
"STRU",
"MODE",
"CWD", //has arg
"PWD", //no arg
"CDUP", //no arg
"PASV", //no arg
"RETR", //has arg
"REST",
"PORT",
"LIST", //no arg
"NLST", //yes/no arg 
"QUIT", //no arg
"SYST", //no arg
"STAT", 
"HELP",
"NOOP",
"STOR",
"APPE",
"STOU",
"ALLO",
"MKD", //has arg
"RMD", //has arg
"DELE", //has arg 
"RNFR",
"RNTO",
"SITE", //has arg    
"FTP_RESPONSE_CODE",
"FTP_RESPONSE_ARG",
"END_FTP_DEFS",
"END_FIELD_DEFS",
"GAUSSIAN",
"UNIFORM",
"FLOW", /* ipv6 flowlabel, should not be last, but may break compatibility if not */
NULL
};


int str2anonid(char *name) {
	int i=0;

	//pattern types are not in the same enumeration
	if(strcmp(name,"INTEGER")==0)
		return 0;
	if(strcmp(name,"STR")==0)
		return 1;

	for(i=0;anonnames[i]!=NULL;i++) {
		if(strcmp(anonnames[i],name)==0) {
			return i;
		}
	}
	return -1;
}
