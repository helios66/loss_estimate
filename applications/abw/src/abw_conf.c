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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#define __USE_XOPEN
#include <time.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "../../src/common/parseconf.h"

#include "abw_common.h"
#include "abw_conf.h"

extern int debug;
int daemonize;

void usage() {
	char *progname="abw";

	fprintf(stderr, "%s: Usage: %s -f <conf_file> [options]\n", progname, progname);

	fprintf(stderr, "  -f <conf_file>   configuration file\n");
	fprintf(stderr, "  -h               print this help message\n");
	fprintf(stderr, "  -d               print debugging messages\n");
	fprintf(stderr, "  -g               run as daemon\n");
	fprintf(stderr, "  -q               do not print results on stdout\n");
	fprintf(stderr, "  -s               print results as numbers only\n");
	fprintf(stderr, "  -c               check configuration file and try to connect to MAPI, do not do measurements (use with -d)\n");

	exit(-1);
} /* usage() */

int read_command_line(int argc, char *argv[], configuration_t *configuration) {

	int opt;

	daemonize=0;

	if (configuration==NULL) {
		fprintf(stderr, "%s: configuration argument is NULL\n", __func__);
		return -1;
	}

	while ((opt=getopt(argc, argv, ARGS)) != -1) {
  	switch(opt) {

		case 'f':
			configuration->global->conf_filename=optarg;
			break;
		case 'h':
			usage();
			exit(0);
		case 'd':
			if (optarg)
				debug=atoi(optarg);
			else
				debug=1;
			break;
		case 'g':
			daemonize=1;
			break;
		case 'q':
			configuration->global->no_stdout=1;
			break;
		case 's':
			configuration->global->stdout_simple=1;
			break;
		case 'c':
         configuration->global->no_measure=1;
         break;

		default:
			usage();
			return -1;
	  }
  }

	if ((configuration->global->conf_filename)==NULL) {
		fprintf(stderr, "%s: configuration filename must be specified\n",
			__func__);
		usage();
		return -1;
	}

	return 0;
} /* read_command_line() */

int read_conf_file(configuration_t *configuration)
{
   conf_category_entry_t *cat;
   conf_parameter_t *param;
   conf_category_t *conf;
	int payload_strings_no;
	subject_t **subject;
	scope_t **scope;
	parameters_t **parameters;
	measurement_t **measurement;

   if (configuration==NULL || configuration->global->conf_filename==NULL) {
      fprintf(stderr, "%s: some of the required arguments were not specified\n",
			__func__);
      return -1;
   }

	/* Parse configuration file and load its content into a sequence of
		structures representing categories and their items in the file */
   if ((conf = pc_load(configuration->global->conf_filename)) == NULL) {
      fprintf(stderr, "%s: pc_load() did not load file %s\n", __func__,
         configuration->global->conf_filename);
      return -1;
   }

	/* Go over all categories */
	subject=&(configuration->subject);
	scope=&(configuration->scope);
	parameters=&(configuration->parameters);
	measurement=&(configuration->measurement);

	cat=pc_get_category(conf, "global");
	if (cat) {

		param=cat->params;
		while (param) {
			if (!strcmp(param->name, "debug"))
            configuration->global->debug=atoi(param->value);
			param=param->next;
		}
	}

	cat=pc_get_category(conf, "subject");
	while (cat) {

		if (*subject==NULL) {
			if ((*subject=new_subject())==NULL) {
				fprintf(stderr, "%s: new_subject() failed\n", __func__);
				return -1;
			}
		}

		param=cat->params;
		while (param) {

			if (!strcmp(param->name, "id"))
            (*subject)->id=atoi(param->value);

			else if (!strcmp(param->name, "hostname")) {
				if (((*subject)->hostname=malloc(strlen(param->value)+1))==NULL) {
					fprintf(stderr, "%s: malloc() failed\n", __func__);
					return -1;
				}
				strcpy((*subject)->hostname, param->value);
			}

			else if (!strcmp(param->name, "interface")) {
				if (((*subject)->interface=malloc(strlen(param->value)+1))==NULL) {
					fprintf(stderr, "%s: malloc() failed\n", __func__);
					return -1;
				}
				strcpy((*subject)->interface, param->value);
			}

			else if (!strcmp(param->name, "port")) {
				/* check here, because -1 given here would look as correct default
               value for check_conf() */
				if (atoi(param->value) < 0) {
					fprintf(stderr, "%s: port number must be >= 0\n", __func__);
					return -1;
				}
        		(*subject)->port=atoi(param->value);
			}

			param=param->next;
		} /* while (param) */
		cat=cat->next;
		subject=&((*subject)->next);
	} /* while (cat) "subject" */
		
	cat=pc_get_category(conf, "scope");
	while (cat) {

		if (*scope==NULL) {
			if ((*scope=new_scope())==NULL) {
				fprintf(stderr, "%s: new_subject() failed\n", __func__);
				return -1;
			}
		}

		param=cat->params;
		while (param) {

			if (!strcmp(param->name, "id"))
            (*scope)->id=atoi(param->value);

			else if (!strcmp(param->name, "subject_ids")) {
				if (((*scope)->subject_ids=malloc(strlen(param->value)+1))==NULL) {
					fprintf(stderr, "%s: malloc() failed\n", __func__);
					return -1;
				}
				strcpy((*scope)->subject_ids, param->value);
			}

			else if (!strcmp(param->name, "label")) {
				if (((*scope)->label=malloc(strlen(param->value)+1))==NULL) {
					fprintf(stderr, "%s: malloc() failed\n", __func__);
					return -1;
				}
				strcpy((*scope)->label, param->value);
			}

			else if (!strcmp(param->name, "description")) {
				if (((*scope)->description=malloc(strlen(param->value)+1))==NULL) {
					fprintf(stderr, "%s: malloc() failed\n", __func__);
					return -1;
				}
				strcpy((*scope)->description, param->value);
			}
		
			else if (!strcmp(param->name, "direction")) {
				if (!strcmp(param->value, "out"))
					(*scope)->out=1;
				else if (!strcmp(param->value, "in"))
					(*scope)->out=0; /* default, just for sure */
				else {
					fprintf(stderr, "%s: direction must be in or out\n", __func__);
					return -1;
				}
			}

			else if (!strcmp(param->name, "mpls"))
            (*scope)->mpls=atoi(param->value);

			else if (!strcmp(param->name, "vlan"))
            (*scope)->vlan=atoi(param->value);

			param=param->next;
		} /* while (param) */
		cat=cat->next;
		scope=&((*scope)->next);
	} /* while (cat) "scope" */
		
	cat=pc_get_category(conf, "parameters");
	while (cat) {

		if (*parameters==NULL) {
			if ((*parameters=new_parameters())==NULL) {
				fprintf(stderr, "%s: new_parameters() failed\n", __func__);
				return -1;
			}
		}

		payload_strings_no=0;
		param=cat->params;
		while (param) {

			if (!strcmp(param->name, "id"))
				(*parameters)->id=atoi(param->value);

			else if (!strcmp(param->name, "header_filter")) {
				if (strlen(param->value)>=MAX_HEADER_FILTER) {
					fprintf(stderr, "%s: header filter string must not be longer than %d characters\n", __func__, MAX_HEADER_FILTER);
					return -1;
				}
				if (((*parameters)->header_filter=
					malloc(strlen(param->value)+1))==NULL) {
						fprintf(stderr, "%s: malloc() failed\n", __func__);
						return -1;
				}
				strcpy((*parameters)->header_filter, param->value);
			}

			else if (!strcmp(param->name, "sau_mode"))
				(*parameters)->sau_mode=param->value[0];

			else if (!strcmp(param->name, "sau_threshold"))
				(*parameters)->sau_threshold=atof(param->value);

			else if (!strcmp(param->name, "payload_string")) {
				if (payload_strings_no >= MAX_PAYLOAD_STRINGS) {
           		fprintf(stderr, "%s: max. %d strings can be searched in payload\n", __func__, MAX_PAYLOAD_STRINGS);
           		return -1;
        		}
        		if (strlen(param->value) > MAX_PAYLOAD_STRING) {
           		fprintf(stderr, "%s: max. %d characters long strings can be searched in payload\n", __func__, MAX_PAYLOAD_STRING);
           		return -1;
        		}
        		if (((*parameters)->payload_strings[payload_strings_no]=
              	malloc(strlen(param->value)+1))==NULL) {
           		fprintf(stderr, "%s: malloc() failed\n", __func__);
           		return -1;
        		}
        		strcpy((*parameters)->payload_strings[payload_strings_no], 
					param->value);
        		payload_strings_no++;
			}
				
			else if (!strcmp(param->name, "interval_sec"))
				(*parameters)->interval.tv_sec=atoi(param->value);

			else if (!strcmp(param->name, "interval_usec"))
				(*parameters)->interval.tv_usec=atoi(param->value);

			param=param->next;
		} /* while (param) */
		cat=cat->next;
		parameters=&((*parameters)->next);
	} /* while (cat) "parameters" */

	cat=pc_get_category(conf, "measurement");
	while (cat) {

		if (*measurement==NULL) {
			if ((*measurement=new_measurement())==NULL) {
				fprintf(stderr, "%s: new_measurement() failed\n", __func__);
				return -1;
			}
		}

		param=cat->params;
		while (param) {

			if (!strcmp(param->name, "id"))
              (*measurement)->id=atoi(param->value);

			if (!strcmp(param->name, "scope_id"))
              (*measurement)->scope_id=atoi(param->value);

			else if (!strcmp(param->name, "parameters_id"))
              (*measurement)->parameters_id=atoi(param->value);

			else if (!strcmp(param->name, "protocols")) {
				if ((*measurement)->protocols) {
					fprintf(stderr, "%s: only one protocols string can be specified\n", __func__);
					return -1;
				}
				if (strlen(param->value) > MAX_PROTOCOLS_STRING) {
               fprintf(stderr, "%s: max. %d characters long protocols string can be specified\n", __func__, MAX_PROTOCOLS_STRING);
               return -1;
            }
            if (((*measurement)->protocols=
						malloc(strlen(param->value)+1))==NULL) {
               fprintf(stderr, "%s: malloc() failed\n", __func__);
               return -1;
            }
				strcpy((*measurement)->protocols, param->value);
			}

			param=param->next;
		} /* while (param) */
		cat=cat->next;
		measurement=&((*measurement)->next);
	} /* while (cat) "measurement" */

	pc_close(conf);

	return 0;
} /* read_conf_file() */

int check_conf(configuration_t *configuration) {
	subject_t *subject;
	scope_t *scope;
	parameters_t *parameters;
	measurement_t *measurement;

	int subject_no;
	int protocols_no;

	int i;

	if (configuration==NULL) {
		fprintf(stderr, "%s: empty configuration\n", __func__);
		return -1;
	}

	/* Check subjects */

   subject=configuration->subject;
   while (subject) {

		if (subject->id <= 0) {
			fprintf(stderr, "%s: id in [subject] section must be greater than zero\n and is %d", __func__, subject->id);
			return -1;
		}
	
		if (subject->interface == NULL) {
			fprintf(stderr, "%s: you must specify interface\n", __func__);
			return -1;
		}

		if (subject->hostname == NULL) {
			fprintf(stderr, "%s: you must specify hostname\n", __func__);
			return -1;
		}

		subject=subject->next;
	} /* while (subject) */

	/* Check scopes */

   scope=configuration->scope;
   while (scope) {

		if (scope->id <= 0) {
			fprintf(stderr, "%s: id in [scope] section must be greater than zero\n", __func__);
			return -1;
		}
	
		if (scope->subject_ids == NULL) {
			fprintf(stderr, "%s: you must specify subject_ids in [scope] section\n", __func__);
			return -1;
		}

		if ((subject_no=split_strings(scope->subject_ids, MAX_SUBJECTS,
				scope->subject_array))<=0) {
			fprintf(stderr, "%s: split_strings() failed\n", __func__);
			return -1;
		}

		if (scope->label == NULL) {
			fprintf(stderr, "%s: you must specify label\n", __func__);
			return -1;
		}

		for (i=0; i<subject_no; i++) {

			subject=configuration->subject;
			while (subject) {
				if (subject->id == atoi(scope->subject_array[i])) {
					scope->subject[i]=subject;
					break;
				}
				subject=subject->next;
			}
			if (!(scope->subject[i])) {
         	fprintf(stderr, 
					"%s: cannot find subject %d refered by scope %d\n",
            		__func__, atoi(scope->subject_array[i]), scope->id);
         	return -1;
      	}

		}

		scope->subject_no = subject_no;

		scope=scope->next;
	} /* while (scope) */

	/* Check parameters */

   parameters=configuration->parameters;
   while (parameters) {

		if (parameters->id <= 0) {
         fprintf(stderr, "%s: id in [parameters] section must be greater than zero\n", __func__);
         return -1;
      }

		if (parameters->sau_mode!='d' && parameters->sau_mode!='b' && 
			 parameters->sau_mode!='p') {
			fprintf(stderr, "%s: sampling mode must be d, b or p\n", __func__);
	  		return -1;
		}

		if (parameters->sau_mode=='p') {
			if (parameters->sau_threshold<0 || parameters->sau_threshold>1) {
		  			fprintf(stderr, "%s: pass probability must be between 0 and 1\n",
						 __func__);
	  	  			return -1;
	  			}
	  		parameters->sau_threshold=
				(floor)(0xFFFFFFFF * (1 - parameters->sau_threshold));
	  		parameters->sau_mode_encoded=COMBO6_PROBABILISTIC;
  		}
  		else if (parameters->sau_mode=='b') {
	  		if (parameters->sau_threshold<0) {
	  			fprintf(stderr, "%s: byte threshold cannot be negative\n", 
					__func__);
	  			return -1;
  			}
			parameters->sau_threshold=(floor)(parameters->sau_threshold);
  			parameters->sau_mode_encoded=COMBO6_LENGTH_DETERMINISTIC;
		}
  		else {
  			if (parameters->sau_threshold<0) {
	  			fprintf(stderr, "%s: packet threshold cannot be negative\n", 
					__func__);
	  			return -1;
  			}
		   parameters->sau_threshold=(floor)(parameters->sau_threshold);
  			parameters->sau_mode_encoded=COMBO6_DETERMINISTIC;
		}

		if (parameters->sau_mode=='b') {
			fprintf(stderr, "%s: byte probabilistic sampling is not supported in this version\n", __func__);
			return -1;
		}

		if (parameters->payload_strings[1]) {
			fprintf(stderr, "%s: payload searching for multiple strings is not supported in this version\n", __func__);
			return -1;
		}

		if (parameters->interval.tv_sec<0 || parameters->interval.tv_usec<0 || 
			 parameters->interval.tv_usec>=1000000 ||
			 (parameters->interval.tv_sec==0 && parameters->interval.tv_usec==0)) {
			fprintf(stderr, "%s: incorrect interval value\n", __func__);
			return -1;
		}

		parameters=parameters->next;
	} /* while (parameters) */

	/* Check measurements */

	measurement=configuration->measurement; 
	while (measurement) {

		if (measurement->id <= 0) {
         fprintf(stderr, "%s: id in [measurement] section must be greater than zero\n", __func__);
         return -1;
      }
		if (measurement->scope_id <= 0) {
			fprintf(stderr, "%s: scope_id in [measurement] section must be greater than zero\n", __func__);
			return -1;
		}
		if (measurement->parameters_id <= 0) {
			fprintf(stderr, "%s: parameters_id in [measurement] section must be greater than zero\n", __func__);
			return -1;
		}

		/* Set default protocol string */

		if (!(measurement->protocols)) {
			if ((measurement->protocols=malloc(strlen("all")+1))==NULL) {
				fprintf(stderr, "%s: malloc() failed\n", __func__);
				return -1;
			}
			strcpy(measurement->protocols, "all");
		}

		/* Split protocol string into individual protocols */

		if ((protocols_no=split_strings(measurement->protocols, MAX_PROTOCOLS,
				measurement->protocols_array))<0) {
			fprintf(stderr, "%s: split_strings() failed\n", __func__);
			return -1;
		}

		/* Sort individual protocols alphabetically */

		qsort(measurement->protocols_array, protocols_no, (size_t)sizeof(char *),
			 compstr);

		/* Replace protocols string with the sorted one */

		free(measurement->protocols);
		if (concat_strings(&(measurement->protocols), MAX_PROTOCOLS,
				measurement->protocols_array)<0) {
			fprintf(stderr, "%s: concat_strings() failed\n", __func__);
			return -1;
		}
	
		/* Check references and set pointers */

		scope=configuration->scope;
		while (scope) {
			if (scope->id == measurement->scope_id) {
				measurement->scope=scope;
				break;
			}
			scope=scope->next;
		}
		if (!(measurement->scope)) {
			fprintf(stderr, "%s: cannot find scope refered by measurement %d\n",
				__func__, measurement->id);
			return -1;
		}

		parameters=configuration->parameters;
		while (parameters) {
			if (parameters->id == measurement->parameters_id) {
				measurement->parameters=parameters;
				break;
			}
			parameters=parameters->next;
		}
		if (!(measurement->parameters)) {
			fprintf(stderr, "%s: cannot find parameters refered by measurement %d\n",
				__func__, measurement->id);
			return -1;
		}

		measurement=measurement->next;
	} /* while (measurement) */

	return 0;
} /* check_conf() */

int print_conf(configuration_t *configuration) {
	measurement_t *measurement;
	char *ch, **chch;
   int i, j;

	if (configuration==NULL) {
		fprintf(stderr, "%s: empty configuration\n", __func__);	
		return -1;
	}

	/* Print global configuration */

	if (configuration->global->conf_filename)
		printf("global->conf_filename: %s\n", configuration->global->conf_filename);
	else
		printf("global->conf_filename: unspecified\n");

	printf("global->no_measure: %d\n", configuration->global->no_measure);
	printf("global->no_stdout: %d\n", configuration->global->no_stdout);
	printf("global->stdout_simple: %d\n", configuration->global->stdout_simple);

	/* Print measurements */

	measurement=configuration->measurement;
   while (measurement) {

		printf("\nmeasurement:\n");
		printf("id: %d\n", measurement->id);
		printf("scope_id: %d\n", measurement->scope_id);
		printf("parameters_id: %d\n", measurement->parameters_id);
		printf("protocols: %s\n", measurement->protocols); 

		/* Print subjects */

		i=0;
		while (i<MAX_SUBJECTS && measurement->scope->subject[i]) {
			printf("subject:\n");
			printf("id: %d\n", measurement->scope->subject[i]->id);
			printf("hostname: %s\n", measurement->scope->subject[i]->hostname);
			printf("interface: %s\n", measurement->scope->subject[i]->interface);
			printf("port: %d\n", measurement->scope->subject[i]->port);
			i++;
		}

		/* Print scope */

		printf("label: %s\n", measurement->scope->label);
		if (measurement->scope->description)
  				printf("description: %s\n", measurement->scope->description);
			else
				printf("description: unspecified\n");
			printf("direction: %s\n", (measurement->scope->out)?
				"out":"in");
	
		/* Print parameters */

		printf("parameters:\n");
		if (measurement->parameters->header_filter)
			printf("header_filter: %s\n", measurement->parameters->header_filter);
		else
			printf("header_filter: unspecified\n");

		printf("sau_mode: %c, sau_threshold: %u\n", 
			measurement->parameters->sau_mode, 
			(unsigned int)(floor(measurement->parameters->sau_threshold)));

		chch=measurement->parameters->payload_strings; 
		j=0;
   	if (*chch) {
			printf("payload_strings:");
			while (j<MAX_PAYLOAD_STRINGS && *chch) {
				ch=*chch;
      		if (j>0)
         		printf(",");
      		printf(" |%s|", ch);
				chch++; j++;
			}
   		printf("\n");
		}
		else
			printf("payload_strings: unspecified\n");
 
  		printf("interval.tv_sec: %d, interval.tv_usec: %d\n", 
			(int)(measurement->parameters->interval.tv_sec), 
			(int)(measurement->parameters->interval.tv_usec));

		measurement=measurement->next;
	} /* while (measurement) */

	return 0;
} /* print_conf() */

int read_header_filter(int argc, char *argv[], char **p) {
	char header_filter[MAX_HEADER_FILTER+1];
	int i;

	header_filter[0]='\0';
	*p=NULL;

  	for (i=optind; i<argc; i++) {
  		if ((strlen(header_filter) + strlen(argv[i])) < MAX_HEADER_FILTER) {
	  		if (i>optind)
		  		strcat(header_filter, " ");
	  		strcat(header_filter, argv[i]);
	  	}
	  	else {
			fprintf(stderr, "%s: header filter string must not be longer than %d characters\n", __func__, MAX_HEADER_FILTER);
	  		exit(-1);
		}
  	}

	if (header_filter[0]) {
		if ((*p=malloc(strlen(header_filter)+1))==NULL) {
			fprintf(stderr, "%s: malloc() failed\n", __func__);
			return -1;
		}
		strcpy(*p, header_filter);
	}
	return 0;
} /* read_header_filter() */

int split_strings(char *input_string, int max_strings, char *string_array[]) {

	int j, k;
	char *chr;
	char string[MAX_STRING+1];
	char *string_start, *string_stop;

	if (input_string==NULL || !input_string[0]) 
		return 0;

	if (strlen(input_string)>MAX_STRING) {
		fprintf(stderr, "%s: input_string string is longer than %d characters\n",
			__func__, MAX_STRING);
		return -1;
	}

	j=0;
	chr=input_string;

	/* go over the whole input_string */
	while (*chr && j<max_strings) {
		/* copy one string, that is until comma ',' or end of input_string */
		k=0;
		while (*chr && *chr!=',') {
			string[k]=*chr;
			k++; chr++;
		}
		string[k]='\0';
		if (k==0) {
			fprintf(stderr, "%s: empty string\n", __func__);
			return -1;
		}

		/* remove leading and trailing spaces and tabs */
		string_start=string;
		while (*string_start==' ' || *string_start=='\t')
			string_start++;
		string_stop=(string+k-1);
		while (*string_stop==' ' || *string_stop=='\t')
			string_stop--;
		if (string_stop<string_start) {
			fprintf(stderr, "%s: empty string\n", __func__);
			return -1;
		}

		if ((string_array[j]=
			malloc(string_stop-string_start+2))==NULL) {
			fprintf(stderr, "%s: malloc() failed\n", __func__);
			return -1;
		}
		strncpy(string_array[j], string_start, 
			string_stop-string_start+1);
		string_array[j][string_stop-string_start+1]='\0';

		if (*chr)
			chr++; /* skip ',' */	
		j++;
	} /* while (*chr && j<max_strings) */

	if (*chr) {
		fprintf(stderr, "%s: more than %d strings\n", __func__,
			max_strings);
		return -1;
	}

	return j;
} /* split_strings() */

int concat_strings(char **output_string, int max_strings, char *string_array[]) {

	int size;
	int i;
	char **chrchr;

	/* Calculate number of characters of output_string */

	size=0;
	chrchr=string_array;	
	i=0;
	while (i<max_strings && *chrchr) {
		size+=strlen(*chrchr);
		chrchr++;
		i++;
	}
	size+=i-1;	/* add space for commas between strings */

	if (size>0) {
		if ((*output_string=malloc(size+1))==NULL) {
			fprintf(stderr, "%s: malloc() failed\n", __func__);
			return -1;
		}
	
		memset(*output_string, 0, size+1);

		/* Concatenate strings */

		chrchr=string_array;
   	i=0;
	   while (i<max_strings && *chrchr) {
			if (i)
				strcat(*output_string, ",");
			strcat(*output_string, *chrchr);
			chrchr++;
			i++;
		}
	}
	/* If string_array was empty, make sure that output_string string is NULL */
	else
		*output_string=NULL;

	return 0;
} /* concat_strings() */

int compstr(const void *str1, const void *str2) {
	char **p1 = (char **) str1;
	char **p2 = (char **) str2;
	return strcmp(*p1, *p2);
} /* compstr() */

