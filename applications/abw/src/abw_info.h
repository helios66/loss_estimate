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

#ifndef __ABW_INFO_H
#define __ABW_INFO_H

#define _GNU_SOURCE
#include <getopt.h>

#define ABW_INFO_ARGS "f:hv"

/* Long option codes */
enum { LO_ABW_INFO_VERBOSE, LO_ABW_INFO_CONF_FILENAME, LO_LABEL, 
	LO_PARAMETERS_ID, LO_DIRECTION };

/* Long option names and argument types */
static const struct option abw_info_long_options[] = {
	{ "verbose",			no_argument,			0,	LO_ABW_INFO_VERBOSE },
	{ "conf_filename",	required_argument,	0,	LO_ABW_INFO_CONF_FILENAME },
	{ "label",				required_argument,	0, LO_LABEL },
	{ "parameters_id",	required_argument,	0,	LO_PARAMETERS_ID },
	{ "direction",			required_argument,	0,	LO_DIRECTION },
	{ 0, 0, 0, 0 }
};

void abw_info_usage(void);

#endif
