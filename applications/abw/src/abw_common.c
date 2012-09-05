/*
 * Copyright (c) 2006, CESNET
 * All rights reserved.
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the company nor the names of its contributors 
 *       may be used to endorse or promote products derived from this 
 *       software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, 
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY 
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL 
 * THE COMPANY OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; 
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id$
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "abw_common.h"
#include "abw_conf.h"

tracked_protocol_t tracked_protocols[] = {
	{ "ftp", "TRACK_FTP" },
	{ "gnutella", "TRACK_GNUTELLA" },
	{ "edonkey", "TRACK_EDONKEY" },
	{ "torrent", "TRACK_TORRENT" },
	{ "dc", "TRACK_DC" },
	{ "skype", "TRACK_SKYPE" },
	{ NULL, NULL },
};

protocol_t protocols[] = {
	{ "ip", "ip" },
	{ "ip6", "ip6" },
	{ "tcp", "tcp" },
	{ "udp", "udp" },
	{ "icmp", "icmp" },
	{ "multicast", "multicast" },
	{ "http", "port 80" },
	{ "https", "port 443" },
	{ "ssh", "port 22" },
	{ NULL, NULL },
};

subject_t *new_subject(void) {
	subject_t *p;

	if ((p=malloc(sizeof(subject_t)))==NULL) {
		fprintf(stderr, "%s: malloc() failed\n", __func__);
		return NULL;
	}

	memset(p, 0, sizeof(subject_t));

	p->port=-1;

	return p;
} /* new_subject() */

scope_t *new_scope(void) {
	scope_t *p;

	if ((p=malloc(sizeof(scope_t)))==NULL) {
		fprintf(stderr, "%s: malloc() failed\n", __func__);
		return NULL;
	}

	memset(p, 0, sizeof(scope_t));

	return p;
} /* new_scope() */

parameters_t *new_parameters(void) {
	parameters_t *p;

	if ((p=malloc(sizeof(parameters_t)))==NULL) {
		fprintf(stderr, "%s: malloc() failed\n", __func__);
		return NULL;
	}

	memset(p, 0, sizeof(parameters_t));

	p->sau_mode='d';
	p->sau_threshold=1;
	p->interval.tv_sec=1;
	p->interval.tv_usec=0;

	return p;
} /* new_parameters() */

measurement_t *new_measurement(void) {
	measurement_t *p;

	if ((p=malloc(sizeof(measurement_t)))==NULL) {
		fprintf(stderr, "%s: malloc() failed\n", __func__);
		return NULL;
	}

	memset(p, 0, sizeof(measurement_t));

	return p;
} /* new_measurement() */

flow_t *new_flow(void) {
   flow_t *p;

   if ((p=malloc(sizeof(flow_t)))==NULL) {
      fprintf(stderr, "%s: malloc() failed\n", __func__);
      return NULL;
   }

   memset(p, 0, sizeof(flow_t));

	return p;
} /* new_flow() */

int protocol_filter(char *header_filter, char *protocol, int mpls, int vlan,
		char **new_header_filter) {

	int new_header_filter_length;
	char *new_protocol;
	int tracked_protocol;
	int i;

	new_protocol=NULL;
	tracked_protocol=0;

	new_header_filter_length=0;

	if (protocol && protocol[0] && strcmp(protocol, "all")) {
		i=0;
		while (protocols[i].protocol) {
			if (!strcmp(protocols[i].protocol, protocol)) {
				new_protocol=protocols[i].filter_string;
				break;
			}
			i++;
		}

		if (!new_protocol) {
			i=0;
			while (tracked_protocols[i].protocol) {
				if (!strcmp(tracked_protocols[i].protocol, protocol)) {
					tracked_protocol=i+1;
					break;
				}
				i++;
			}
		}

		if (new_protocol==NULL && tracked_protocol==0) {
			fprintf(stderr, "%s: unknown protocol %s\n", __func__, protocol);
			return -1;
		}	
	}

	/* Find length of new_header_filter */

	if (mpls)
		new_header_filter_length+=strlen("mpls");

	if (vlan)
		new_header_filter_length+=strlen("vlan");

	if (new_protocol) {
		if (new_header_filter_length)
			new_header_filter_length+=strlen(" and ");
		new_header_filter_length+=strlen(new_protocol);
	}

	if (header_filter) {
		if (new_header_filter_length)
			new_header_filter_length+=strlen(" and ");
		new_header_filter_length+=strlen(header_filter);
	}

	/* Allocate memory for new_header_filter and fill it */

	if (new_header_filter_length) {
		if ((*new_header_filter=malloc(new_header_filter_length+1))==NULL) {
			fprintf(stderr, "%s: malloc() failed\n", __func__);
			return -1;
		}
		memset(*new_header_filter, 0, new_header_filter_length+1);

		if (mpls)
			strcpy(*new_header_filter, "mpls");

		if (vlan)
			strcpy(*new_header_filter, "vlan");

		if (new_protocol) {
			if (strlen(*new_header_filter))
				strcat(*new_header_filter, " and ");
			strcat(*new_header_filter, new_protocol);
		}

		if (header_filter) {
			if (strlen(*new_header_filter))
				strcat(*new_header_filter, " and ");
			strcat(*new_header_filter, header_filter);
		}
	}
	else
		*new_header_filter=NULL;

	return tracked_protocol;
} /* protocol_filter() */

int get_local_hostname(char **hostname) {

	char buffer[MAX_HOSTNAME+1];
	struct hostent *hostent;

	if (gethostname(buffer, MAX_HOSTNAME+1)<0) {
		fprintf(stderr, "%s: gethostname() failed\n", __func__);
		return -1;
	}
	buffer[MAX_HOSTNAME]='\0';

	if ((hostent=gethostbyname(buffer))==NULL) {
		fprintf(stderr, "%s: gethostbyname() failed\n", __func__);
		return -1;
	}

	if ((*hostname=malloc(strlen(hostent->h_name)+1))==NULL) {
		fprintf(stderr, "%s: malloc() failed\n", __func__);
		return -1;
	}
	strcpy(*hostname, hostent->h_name);

	return 0;
} /* get_local_hostname() */

int timestamp_diff(struct timeval *tv_start, struct timeval *tv_stop) {
	int sec, usec;

	if (tv_start==NULL || tv_stop==NULL) {
		fprintf(stderr, "%s: tv_start or tv_stop is NULL\n", __func__);
		return -1;
	}

	usec=0;

	/* printf("tv_start->tv_sec: %u, tv_start->tv_usec: %u\n",
		(unsigned int)(tv_start->tv_sec), (unsigned int)(tv_start->tv_usec));
	printf("tv_stop->tv_sec: %u, tv_stop->tv_usec: %u\n",
		(unsigned int)(tv_stop->tv_sec), (unsigned int)(tv_stop->tv_usec)); */

	sec=tv_stop->tv_sec - tv_start->tv_sec;

	if (sec<0) {
		fprintf(stderr, "%s: stop is less than start\n", __func__);
		return -1;
	}

	if (sec>1)
		usec = (tv_stop->tv_sec - tv_start->tv_sec - 1)*1000000;
	
	if (sec)
		usec += 1000000-tv_start->tv_usec + tv_stop->tv_usec;
	else 
		usec = tv_stop->tv_usec - tv_start->tv_usec;

	if (usec<0) {
	  fprintf(stderr, "%s: stop is less than start\n", __func__);
     return -1;
   }

	return usec;
} /* timestamp_diff() */

int continue_as_daemon(void) {
	int nullfd;

	printf("Closing stdin, stdout, stderr and going into background.\n");

	switch (fork()) {
		case 0: 
			break;
		case -1:
			fprintf(stderr, "%s: fork() failed, %d - %s\n", __func__, errno, 
				strerror(errno));
			return -1;
			break;
		default:
			_exit(0);
			break;
	}
	if (setsid() == -1) {
		fprintf(stderr, "%s: setsid() failed, %d - %s\n", __func__, errno, 
			strerror(errno));
		return -1;
	}
	setpgrp();
	switch (fork()) {
		case 0: 
			break;
		case -1:
			fprintf(stderr, "%s: fork() failed, %d - %s\n", __func__, errno, 
				strerror(errno));
			return -1;
			break;
		default:
			_exit(0);
			break;
	}

	chdir("/");
	
	nullfd = open("/dev/null", O_RDONLY);
	dup2(nullfd, STDIN_FILENO);
	close(nullfd);
	nullfd = open("/dev/null", O_WRONLY);
	dup2(nullfd, STDOUT_FILENO);
	dup2(nullfd, STDERR_FILENO);
	close(nullfd);

	return 0;
}

