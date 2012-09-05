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
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

#include "abw_rrd.h"
#include "abw_common.h"
#include "abw_conf.h"

extern int debug;

/* /directory/hostname1-interface1-port1,hostname2-interface2-port2, ... 
		-parameters-protocol.rrd */

char *abw_rrd_create_filename(scope_t *scope, int parameters_id, 
	char *protocol) {

	static char rrd_filename[MAX_RRD_FILENAME+1];
	char *ch;
	int i;

	strcpy(rrd_filename, RRD_DIRECTORY);

	/* pointer after /directory/ where / must be replaced with _ */

	ch=rrd_filename + strlen(RRD_DIRECTORY);

	i=0;
  	while (scope->subject[i] && i<MAX_SUBJECTS) {

		/* Append comma "," */

		if (i) {
			if (strlen(rrd_filename)+1>=MAX_RRD_FILENAME) {
				fprintf(stderr, "%s: RRD filename is longer than %d characters\n", 
					__func__, MAX_RRD_FILENAME);
				return NULL;
			}
			strcat(rrd_filename, ",");
		}

		/* Append next hostname-interface-port */
		
		if (strlen(rrd_filename) +
			strlen(scope->subject[i]->hostname) +
 			strlen(scope->subject[i]->interface) +
			5 + 2 /* 5 for port, 1 for - and 1 for - */
				>= MAX_RRD_FILENAME) {
     			fprintf(stderr, "%s: RRD filename is longer than %d characters\n", 
					__func__, MAX_RRD_FILENAME);
        		return NULL;
     		}
		sprintf(rrd_filename + strlen(rrd_filename), "%s-%s-%d",
		scope->subject[i]->hostname,
		scope->subject[i]->interface,
		(scope->subject[i]->port)>=0?scope->subject[i]->port:0);
			
		i++;
	} /* while (scope->subject[i] && i<MAX_SUBJECTS) */

	/* Replace '/' with '_' */
	while (*ch) {
		if (*ch=='/')
			*ch='_';
		ch++;
	}

	/* If we do not use parameters, still append default "1" for
		compatibility with scripts */

	if (parameters_id>0)
		sprintf(rrd_filename+strlen(rrd_filename), "-%d", parameters_id);
	else
		sprintf(rrd_filename+strlen(rrd_filename), "-1");

	if (protocol)
		sprintf(rrd_filename+strlen(rrd_filename), "-%s", protocol);

	/* 
	 * If protocol is specified, this is a full RRD filename. If protocol is not
	 * specified, this is a prefix for rrd_graph... scripts.
	 */

	if (protocol)
		strcat(rrd_filename, ".rrd");

	if ((ch=malloc(strlen(rrd_filename)+1))==NULL) {
		fprintf(stderr, "%s: malloc() failed\n", __func__);
		return NULL;
	}
	strcpy(ch, rrd_filename);
	
	return ch;
} /* abw_rrd_create_filename() */

int abw_rrd_create_file(char *filename) {

	struct stat rrd_file_stat;
	char command[MAX_COMMAND+1];

	memset((void *)&rrd_file_stat, 0, (size_t)sizeof(rrd_file_stat));
	
   if (stat(filename, &rrd_file_stat)<0) {
		if (errno!=ENOENT) {
			fprintf(stderr, "%s: stat() failed\n", __func__);
			return -1;
	   }
		if (debug)
			printf("%s: RRD file %s does not exist, it will be created\n",
					 __func__, filename);
		sprintf(command, "%s %s", RRD_CREATE_LINK_SCRIPT, filename);
		if (debug)
			printf("%s: system(%s)\n", __func__, command);
		if (system(command)<0) {
			fprintf(stderr, "%s: system(%s) failed\n", __func__, command);
			return -1;
		}
	}
	else {
		if (debug)
			printf("%s: Ok, RRD file %s already exists\n", __func__, filename);
	}

	return 0;
} /* abw_rrd_create_file() */
