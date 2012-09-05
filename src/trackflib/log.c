#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <dirent.h>
#include "log.h"

#define KB 1024
#define MB 1024 * KB
#define LOG_SIZE 100 * MB

static FILE *fp = NULL;
static int log_mutex;
static int initdone = 0;

char *get_protocol(int proto);
void renew_log_file(void);
void init_log(void);

// keep onlu last 2 log files in order  to debug
char *filename_prev;
char *filename_pprev;
char *filename_cur;

char *get_protocol(int proto) {
	if(proto == 6)
		return "TCP";
	if(proto == 17)
		return "UDP";

	return "UNKNOWN";	
}

void init_log()
{
	filename_pprev = NULL;
	filename_prev = NULL;
	filename_cur = NULL;
	renew_log_file();
	log_mutex = 0;
}

void renew_log_file(void) 
{
	int i = 0;
	time_t timep;
	char filename[50] = "\0";
	char *tim = NULL;
	DIR *dir = NULL;
	char buf[100];
	
	if(filename_pprev != NULL) {
		sprintf(buf, "rm %s", filename_pprev); 
		system(buf);
		free(filename_pprev);
	}
	filename_pprev = filename_prev;
	filename_prev = filename_cur;

	if(fp != NULL) {
		fclose(fp);
	}

	time(&timep);
	tim = ctime(&timep);

	for(i = 0; tim[i] != '\n'; i++) {
		if(tim[i] == ' ' || tim[i] == ':') {
			tim[i] = '_';
		}
	}
	
	tim[i] = '\0';

	if((dir = opendir("/usr/local/mapi/log")) == NULL) { // TODO: check all error cases.
		system("mkdir /usr/local/mapi/log");
	}
	else 
		closedir(dir);

	sprintf(filename, "/usr/local/mapi/log/%s.log", tim);
	filename_cur = strdup(filename);

	fp = fopen(filename, "w");
}

void write_to_log(char *proto, char *string, int protocol, struct in_addr  sip, uint16_t  sp, struct in_addr dip, uint16_t dp, unsigned char *packet, unsigned int len) 
{
	static unsigned long long file_count = 0;
	unsigned int i = 0;
	char *str = strdup(string);
	char *p = NULL;
	
	while(__sync_lock_test_and_set(&log_mutex,1));

	if(initdone == 0) {
		init_log();
		initdone = 1;
	}
	
	p = str;
	
	while(p != NULL && *p != '\0') {
		if(isspace(*p)) {
			*p = '_';
		}
		p++;
	}

	file_count += fprintf(fp, "%s %s %s %s:%d ",proto, str, get_protocol(protocol), inet_ntoa(sip), sp);
	file_count += fprintf(fp, "%s:%d\t", inet_ntoa(dip), dp);

	for(i = 0; i < 100 && i < len; i++) {
		if(isprint(packet[i])){
			file_count += fprintf(fp, "%c", packet[i]);
		}
		else if(packet[i] == '\n') {			
			file_count += fprintf(fp, ".");
		}
		else {
			file_count += fprintf(fp, ".");
		}
	}
	
	file_count += fprintf(fp, "\n");

	if(file_count > LOG_SIZE) {
		renew_log_file();
		file_count = 0;
	}

	free(str);
	log_mutex = 0;
}
