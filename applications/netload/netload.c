#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <ncurses.h>
#include <mapi.h>

#define MAX_INTERFACES 32

static void terminate();
int fd;

typedef struct statistics {
	unsigned long long prev_bytes;
	unsigned long long prev_ts;
} stats_t;

int main(int argc, char **argv) {

	int fid;
	mapi_results_t *res;
	int row, col, i, scope_strlen=0, maxpad=13;
	char *scope;

	int scope_size;

	stats_t stats[MAX_INTERFACES] = {{0,0}};

	if(argc < 2){
		printf("usage: %s interface1\n", argv[0]);
		printf("       %s host1:interface1 host2:interface2 ...\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	printf("scope:\n");
	for(i=1; i<argc; ++i) {
		printf("%s\n", argv[i]);
		scope_strlen += strlen(argv[i]);
		if ((int)strlen(argv[i]) > maxpad)
			maxpad = strlen(argv[i]);
	}
	
	/* allocate memory for the scope string */
	scope = (char *)malloc(scope_strlen + argc-2 + 1);
	if (scope == NULL) {
		perror("Could not allocate memory");
		exit(EXIT_FAILURE);
	}
	
	/* concatenate interfaces into the scope string */
	*scope = '\0';
	for (i=1; i<argc; ++i) {
		strncat(scope, argv[i], 64);
		if (i < argc-1)
			strcat(scope, ",");
	}

	signal(SIGINT, terminate);
	signal(SIGQUIT, terminate);
	signal(SIGTERM, terminate);

	if ((fd = mapi_create_flow(scope)) < 0) {
		printf("Could not create flow\n");
		exit(EXIT_FAILURE);
	}

	if ((fid = mapi_apply_function(fd, "BYTE_COUNTER")) < 0) {
		printf("Could not apply BYTE_COUNTER to flow %d\n", fd);
		exit(EXIT_FAILURE);
	}

	/* connect to the flow */
	if (mapi_connect(fd) < 0) {
		printf("Could not connect to flow %d\n", fd);
		exit(EXIT_FAILURE);
	}

	initscr();	/* start curses mode */
	getmaxyx(stdscr,row,col);  /* get the number of rows and columns */

	scope_size = mapi_get_scope_size(fd);
	if (scope_size > MAX_INTERFACES) {
	printf("Scope size (%d) is too big. Please use %d or less interfaces\n",
				scope_size, MAX_INTERFACES);
	exit(EXIT_FAILURE);
	}
	
	while(1) {      /* forever, report the load */
		
		unsigned long long bytes=0, ts=0;
		float speed;
        
		sleep(1);
		
		res = mapi_read_results(fd, fid);
		
		for (i=0; i<scope_size; i++) {
			bytes = *((unsigned long long *)res[i].res);
			ts = res[i].ts;
			speed = (bytes - stats[i].prev_bytes)*8 / (float)(ts - stats[i].prev_ts);
			mvprintw(row/2+i+1, 8, "%*s: %6.2f Mbit/s  %8llu bytes in %1.2f seconds\n",
				maxpad, argv[i+1], speed, (bytes - stats[i].prev_bytes), 
				(double)(ts-stats[i].prev_ts)/1000000.0);
			stats[i].prev_bytes = bytes;
			stats[i].prev_ts = ts;
		}
		refresh();
    }
    return 0;
}

void terminate() {
    mapi_close_flow(fd);
	endwin(); /* end curses */
    exit(EXIT_SUCCESS);
}
