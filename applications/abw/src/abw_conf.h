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

#ifndef __ABW_CONF_H
#define __ABW_CONF_H

#define _GNU_SOURCE
#include <getopt.h>

/* 
 * Leading colon ":" makes getopt() to return colon ":" rather than
 * a question mark "?" when option argument is missing (and it returns
 * "?" for unknown option). In this way we can distinquish between
 * options with optional arguments and unknown options.
 *
 * But getopt() also allows to specify directly an option without argument
 * as not followed by ":" and an option with an optional argument as
 * followed by "::".
 */
#define ARGS ":f:hdgqsc"

/* Long option codes */
/* enum {
	LO_CONF_FILENAME, LO_NO_MEASURE, LO_NO_STDOUT, LO_STDOUT_SIMPLE,
	LO_DEBUG, LO_DAEMON }; */

/* Long option names and argument types */
/* static const struct option long_options[] = {
	{ "conf_filename",	required_argument,	0,	LO_CONF_FILENAME },
	{ "no_measure",		no_argument,			0, LO_NO_MEASURE },
	{ "no_stdout",			no_argument,			0,	LO_NO_STDOUT },
	{ "stdout_simple",	no_argument,			0,	LO_STDOUT_SIMPLE },
	{ "debug",				optional_argument,	0,	LO_DEBUG },
	{ "daemon",				no_argument,			0,	LO_DAEMON },
	{ 0, 0, 0, 0 }
}; */

#define DEFAULT_HOSTNAME "localhost"
#define DEFAULT_INTERFACE "eth0"
#define DEFAULT_LINK_MBPS    0   /* No default link speed, must be specified */
#define DEFAULT_PROTOCOLS "all"

#define MAX_HOSTNAME			128
#define MAX_HEADER_FILTER 	256
#define MAX_PAYLOAD_STRING	 16   /* max. characters of payload string */
#define MAX_PAYLOAD_STRINGS 16   /* max. number of payload strings */
#define MAX_STRING         256	/* max. characters of various strings */
#define MAX_PROTOCOLS_STRING 		256
#define MAX_PROTOCOLS 	 	 32
#define MAX_SUBJECTS			 32
#define MAX_FLOWS			 	128	/* scopes * protocols */

typedef enum {
        COMBO6_DETERMINISTIC,
        COMBO6_LENGTH_DETERMINISTIC,
        COMBO6_PROBABILISTIC
} sau_modes_t;

typedef struct subject_struct {
  int id;
  char *hostname;
  char *interface;
  int port;

  struct subject_struct *next;
} subject_t;

typedef struct scope_struct {
  int id;
  char *subject_ids;
  subject_t *subject[MAX_SUBJECTS];

  /* Alternative representation, conversion done in check_conf() */
  char *subject_array[MAX_SUBJECTS];
  int subject_no;

  int mpls;
  int vlan;
  int out;
  char *label;
  char *description;

  struct scope_struct *next;
} scope_t;

typedef struct parameters_struct {
  int id;
  char *header_filter;
  char sau_mode;
  double sau_threshold;
  char *payload_strings[MAX_PAYLOAD_STRINGS];
  struct timeval interval;

  /* Alternative representation, conversion done in check_conf() */
  int sau_mode_encoded;

  struct parameters_struct *next;
} parameters_t;

typedef struct measurement_struct {
  int id;
  int scope_id;
  int parameters_id;
  scope_t *scope;
  parameters_t *parameters;
  char *protocols;

  /* Alternative representation, conversion done by split_strings() */
  char *protocols_array[MAX_PROTOCOLS];

  struct measurement_struct *next;
} measurement_t;

typedef struct global_struct {
  char *hostname;				/* local hostname including domain name */
  char *conf_filename;		/* read configuration from this file */
  int no_measure;				/* if non-zero do not do measurements 
                              (only process configuration) */
  int no_stdout;				/* if non-zero do not print results to stdout */
  int stdout_simple;			/* if non-zero print results as numbers only */
  int debug;					/* debug level */

} global_t;

typedef struct configuration_struct {
	subject_t *subject;
	scope_t *scope;
	parameters_t *parameters;
	measurement_t *measurement;
	global_t *global;
} configuration_t;

subject_t *new_subject(void);

scope_t *new_scope(void);

parameters_t *new_parameters(void);

measurement_t *new_measurement(void);

void usage(void);

int read_command_line(int argc, char *argv[], configuration_t *configuration);

int read_conf_file(configuration_t *configuration);

int read_const_conf_file(configuration_t *configuration);

int check_conf(configuration_t *configuration);

int print_conf(configuration_t *configuration);

int read_header_filter(int argc, char *argv[], char **p);

int split_strings(char *input_string, int max_strings, char *string_array[]);

int concat_strings(char **output_string, int max_strings, char *string_array[]);

int compstr(const void *str1, const void *str2);

#endif
