/* File: testcompiler.c
 *
 * Test part of the Ruler filtering process by dynamically loading
 * a Ruler filter module, and invoking it.
 */

#include <dlfcn.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>

#define FILTER_NAME "filter.rl"
#define BUFSIZE 200

#include "helper-functions.h"

static void run_filter( process_packet_t *filter, const char *in, const char *out )
{
    unsigned char inbuf[BUFSIZE];
    unsigned char outbuf[BUFSIZE];
    unsigned int outlen;
    size_t insz = strlen( in );
    size_t outsz = strlen( out );

    memcpy( inbuf, in, insz );
    int res = (*filter)( inbuf, insz, outbuf, &outlen );
    if( !res ){
	fprintf( stderr, "Filter rejected input '%s'\n", in );
	exit( 1 );
    }
    if( outsz != outlen || strncmp( (char *) outbuf, out, outsz ) != 0 ){
	outbuf[outlen] = '\0';
	fprintf( stderr, "Unexpected filter output\n" );
	fprintf( stderr, "I exected %2u bytes: '%s'\n", (unsigned) outsz, out );
	fprintf( stderr, "I got     %2u bytes: '%s'\n", outlen, outbuf );
	exit( 1 );
    }
}

int main()
{
    instance_info *info;
    char *filter = qualify_file( FILTER_NAME );

    info = create_ruler_filter( filter );
    if( info == NULL ){
        fprintf( stderr, "Cannot create a filter module for `%s'\n", FILTER_NAME );
        exit( 1 );
    }
    run_filter( info->processor, "abc", "abc" );
    run_filter( info->processor, "ABCDEF", "ABCDEF" );
    run_filter( info->processor, "++james++", "++XXX++" );

    destroy_ruler_filter( info );

    free( filter );
    exit( 0 );
    return 0;
}
