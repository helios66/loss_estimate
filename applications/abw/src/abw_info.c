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

#include "abw_conf.h"
#include "abw_rrd.h"
#include "abw_info.h"

char *progname="abw_info";
int debug=0;

void abw_info_usage(void) {
	fprintf(stderr, "Usage: %s -h (help)\n", progname);
	fprintf(stderr, "                -v or --verbose\n");
	fprintf(stderr, "                -f or --conf_filename <conf_filename>\n");
	fprintf(stderr, "                --label <label>\n");
	fprintf(stderr, "                --parameters_id <parameters_id> (default 1)\n");
	fprintf(stderr, "                --direction { in | out } (default both directions)\n");
	fprintf(stderr, "\nTo print which (label, parameters_id, direction) tuples exist:\n\n");
	fprintf(stderr, "%s -f abw.conf\n", progname);
	fprintf(stderr, "\nTo print information about a specific (label, parameters_id, direction) tuple:\n");
	fprintf(stderr, "%s -f abw.conf --label=Prague_PoP\n", progname);
	fprintf(stderr, "%s -f abw.conf --label=Prague_PoP --parameters_id=2\n", progname);
	fprintf(stderr, "%s -f abw.conf --label=Prague_PoP --parameters_id=2 --direction=out\n", progname);
} /* usage() */

int main(int argc, char *argv[])
{ 
	configuration_t configuration;
	int verbose=0;
	char *label=NULL;
	int parameters_id=0;
	char *direction=NULL;
	char *conf_filename=NULL;
	measurement_t *measurement;
	scope_t *scope_in=NULL, *scope_out=NULL;
	char *prefix_in=NULL, *prefix_out=NULL;
	int opt;
   int opt_idx;

	if (argc<2) {
		abw_info_usage();
		return -1;
	}

	while ((opt=getopt_long(argc, argv, ABW_INFO_ARGS, abw_info_long_options, 
		&opt_idx)) != -1) {

  		switch(opt) {

			/* General options */
			case 'h':
				abw_info_usage();
				return 0;
			case 'v':
			case LO_ABW_INFO_VERBOSE:
				verbose=1;
				break;
			case 'f':
			case LO_ABW_INFO_CONF_FILENAME:
				if (conf_filename) {
					fprintf(stderr, "%s: only one -f or --conf_filename argument can be specified\n", progname);
					return -1;
				}
				conf_filename=optarg;
				break;
			case LO_LABEL:
				if (label) {
					fprintf(stderr, "%s: only one --label argument can be specified\n", progname);
					return -1;
				}
				label=optarg;
				break;
			case LO_PARAMETERS_ID:
				if (parameters_id) {
					fprintf(stderr, "%s: only one --parameters_id argument can be specified\n", progname);
					return -1;
				}
				parameters_id=atoi(optarg);
				if (parameters_id<=0) {
         	   fprintf(stderr, "%s: parameters_id must be positive\n", 
						progname);
            	return -1;
         	}
				break;
			case LO_DIRECTION:
				if (direction) {
					fprintf(stderr, "%s: only one --direction argument can be specified\n", progname);
					return -1;
				}
				direction=optarg;
				if (strcmp(direction, "in") && strcmp(direction, "out")) {
					fprintf(stderr, "%s: direction must be in or out\n", progname);
					return -1;
				}
				break;
			default:
				fprintf(stderr, "%s: unknown argument\n", __func__);
         	abw_info_usage();
         	return -1;
		} /* switch(opt) */
	}

	if (verbose) {
		if (!label) {	
			fprintf(stderr, "%s: verbose mode can be used only when label is specified\n", __func__);
			return -1;
		}
	}

	/* parameters_id was not specified, set it to default value */

	if (!parameters_id)
		parameters_id=1;

	memset((void *)&configuration, 0, (size_t)(sizeof(configuration)));

	/* Create global configuration */
	if ((configuration.global=malloc(sizeof(global_t)))==NULL) {
		fprintf(stderr, "%s: malloc() failed\n", __func__);
		return -1;
	}
	memset(configuration.global, 0, sizeof(global_t));

	configuration.global->conf_filename=conf_filename;

	/* Read configuration file */

	if (read_conf_file(&configuration)<0) {
		fprintf(stderr, "%s: read_conf_file() failed\n", __func__);
		return -1;
	}

	/* Check if specified values are within acceptable limits */

	if (check_conf(&configuration)<0) {
      fprintf(stderr, "%s: check_conf() failed\n", __func__);
      return -1;
	}

	/* Go over all measurements */

	measurement=configuration.measurement;
   while (measurement) {

		/* 
		 * If no --label was specified,
		 *	just print all valid tuples (label, parameters_id, direction) 
		 */

		if (!label)
			 printf("%s %d %s\n", measurement->scope->label,
          	measurement->parameters_id, 
				(measurement->scope->out)?"out":"in");

		/*
		 * If this is specified --label and parameters_id, then remember it, 
		 * there can be two scopes for in and out direction
		 */

		if (label && !strcmp(label, measurement->scope->label) &&
			parameters_id==measurement->parameters_id) {
			if (measurement->scope->out)
              scope_out=measurement->scope;
           else
              scope_in=measurement->scope;
			if (scope_in && scope_out)
				break; /* we do not need to search remaining subjects */
		}

		measurement=measurement->next;

	} /* while (measurement) */

	if (!label)
		return 0;

	if (label && !direction && !scope_in && !scope_out)
		printf("Unknown (label, parameters_id, direction) tuple\n");

	if (label && direction && 
			((!strcmp(direction, "in") && !scope_in) ||
		 	(!strcmp(direction, "out") && !scope_out)))
		printf("Unknown label and direction combination\n");

	if (scope_in) {
		if ((prefix_in=abw_rrd_create_filename(scope_in, parameters_id, 
			NULL))==NULL){
				fprintf(stderr, "%s: abw_rrd_create_filename() failed\n", __func__);
				return -1;
			}
	}

	if (scope_out) {
		if ((prefix_out=abw_rrd_create_filename(scope_out, parameters_id, 
			NULL))==NULL){
				fprintf(stderr, "%s: abw_rrd_create_filename() failed\n", __func__);
				return -1;
			}
	}

	if (verbose) {
		if (scope_in && (!direction || !strcmp(direction, "in"))) {
			printf("label_in: %s\n", scope_in->label);
			printf("parameters_id: %d\n", parameters_id);
			printf("description_in: %s\n",
				(scope_in->description)?scope_in->description:"");
			printf("prefix_in: %s\n", prefix_in);
		}
		if (scope_out && (!direction || !strcmp(direction, "out"))) {
			printf("label_out: %s\n", scope_out->label);
			printf("parameters_id: %d\n", parameters_id);
			printf("description_out: %s\n",
				(scope_out->description)?scope_out->description:"");
			printf("prefix_out: %s\n", prefix_out);
		}
	}
	else {
		if (scope_in && (!direction || !strcmp(direction, "in"))) {
        	printf("scope: %s %s \"%s\"\n", label, prefix_in,
              (scope_in->description)?(scope_in->description):"");
		}
		if (scope_out && (!direction || !strcmp(direction, "out"))) {
        	printf("scope: %s %s \"%s\"\n", label, prefix_out,
              (scope_out->description)?(scope_out->description):"");
		}
	}

	return 0;
} /* main() */
