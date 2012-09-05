#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <pcre.h>
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"
#include "mapi_errors.h"
#include "debug.h"

struct mapid_regexp {
	char *pattern;
	pcre *compiled_pattern;

};

#define OVECCOUNT 30    /* should be a multiple of 3 */


static int regexp_process(mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			MAPI_UNUSED unsigned char* link_pkt,
			MAPI_UNUSED mapid_pkthdr_t* pkt_head)  
{
	int rc;
	struct mapid_regexp *data=(struct mapid_regexp *)(instance->internal_data);
	int   ovector[OVECCOUNT];

	rc = pcre_exec (data->compiled_pattern,         /* the compiled pattern */
		    0,                    		/* no extra data - pattern was not studied */
		    (const char *) link_pkt,            /* the string to match */
		    pkt_head->caplen,
		    0,                    		/* start at offset 0 in the subject */
		    0,                    		/* default options */
		    ovector,              		/* output vector for substring information */
		    OVECCOUNT);           		/* number of elements in the output vector */

	if (rc < 0) {
		return 0;
    	}
	
    return 1;
}

static int regexp_instance(mapidflib_function_instance_t *instance,
			   MAPI_UNUSED int flow_descr,
			   MAPI_UNUSED mapidflib_flow_mod_t *flow_mod)
{
	char *pattern, *error;
	pcre *compiled_pattern;
	int erroffset;
	
	mapiFunctArg* fargs = instance->args;
	pattern = getargstr(&fargs);

	if(!pattern)
		return(MFUNCT_INVALID_ARGUMENT);

	if(pattern == NULL)
		return(MFUNCT_INVALID_ARGUMENT);

	if((compiled_pattern = pcre_compile(pattern, 0, (const char **) &error, &erroffset, 0)) == NULL){

		DEBUG_CMD(Debug_Message("pcre_compile failed (offset: %d), %s", erroffset, error));
		return(MFUNCT_INVALID_ARGUMENT);
	}

	pcre_free(compiled_pattern);		// free pcre struct point

	return(0);
}

static int regexp_init(mapidflib_function_instance_t *instance, MAPI_UNUSED int fd)
//Initializes the function
{
	struct mapid_regexp *data;
	mapiFunctArg* fargs;
	char *str,*error;
	int erroffset;

	instance->internal_data = malloc(sizeof(struct mapid_regexp));
	data=(struct mapid_regexp *)(instance->internal_data);
	
 	fargs=instance->args;
	str = getargstr(&fargs);
	data->pattern=strdup(str);

	data->compiled_pattern= pcre_compile (data->pattern,0, (const char **) &error, &erroffset,0);       
	
	if (!(data->compiled_pattern)) {
		DEBUG_CMD(Debug_Message("pcre_compile failed (offset: %d), %s", erroffset, error));
		return MFUNCT_INVALID_ARGUMENT_1;
  	}

	return 0;
}

static int regexp_cleanup(mapidflib_function_instance_t *instance){

	struct mapid_regexp *data;

	data = (struct mapid_regexp *)(instance->internal_data);

	pcre_free(data->compiled_pattern);		// free pcre struct point
	free(data->pattern);
	free(data);

	return 0;
}

static mapidflib_function_def_t regexp_finfo={
    "", //libname
    "REGEXP", //name
    "Regular expression pattern matching\n\tTakes a regular expression string as an argument", //descr
    "s", //argdescr
    MAPI_DEVICE_ALL, //devoid
    MAPIRES_NONE, //Use shared memory to return results
    0, //shm size
    0, //modifies_pkts
    1, //filters packets
    MAPIOPT_NONE,
    regexp_instance,  //instance
    regexp_init, //init
    regexp_process,
    NULL, //get_result,
    NULL,
    regexp_cleanup, //cleanup
    NULL, //client_init
    NULL, //client_read_result
    NULL  //client_cleanup
};

mapidflib_function_def_t* regexp_get_funct_info();

mapidflib_function_def_t* regexp_get_funct_info() {
    return &regexp_finfo;
};
