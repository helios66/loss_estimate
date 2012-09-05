#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>	      /* for Unix domain sockets: struct sockaddr_un */
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include "appmon.h"
#include "util.h"
#include <cgic.h>

extern int daemon_proc;

int cgiMain() {

	char name[81];
	char buf[MAXLINE];
	
	int result, invalid, i;
	int filter_choices[NUMFILTERS];
	char *filter_names[NUMFILTERS];
	
	int sockfd;
	struct sockaddr_un servaddr;

	daemon_proc = 1; /* syslog instead of stderr for err_* functions */

	if ((sockfd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0)
		err_sys("socket error");
    
	/* create the address we will be connecting to */
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sun_family = AF_LOCAL;
	strcpy(servaddr.sun_path, UNIXSTR_PATH);
	
	if (connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0)
		err_sys("connect error");
	
	result = cgiFormStringNoNewlines("subnet", name, 81);
	if (result == cgiFormEmpty)
		snprintf(name, 81, "empty");

	for (i=0; i<NUMFILTERS; ++i)
		filter_names[i] = filter[i].name;
	
	result = cgiFormCheckboxMultiple("filters", filter_names, NUMFILTERS, filter_choices, &invalid);

	Writen(sockfd, filter_choices, NUMFILTERS*sizeof(int));
	Writen(sockfd, name, strlen(name)+1); // send '\0'
	Readn(sockfd, buf, 3);
	
	cgiHeaderContentType("text/html");
	fprintf(cgiOut, "<HTML>\n<HEAD>\n</HEAD>\n");
	fprintf(cgiOut, "<BODY><meta http-equiv=\"refresh\" content=\"0;url=../appmon_form.html\">\n");
	fprintf(cgiOut, "</BODY></HTML>\n");
	return 0;
}
