#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include "mapi.h"

#define BUFSIZE 10000

static char errstr[520];
static char filterpath[BUFSIZE];

static void dump_packet( FILE *f, const unsigned char *buf, unsigned int sz )
{
    unsigned int i;
    int in_string = 0;

    for( i=0; i<sz; i++ ){
	unsigned char c = buf[i];

	if( c>=' ' && c<0x7f ){
	    if( !in_string ){
		fputs( "\" ", f );
		in_string = 1;
	    }
	    fputc( c, f );
	}
	else {
	    if( in_string ){
		fputs( "\" ", f );
		in_string = 0;
	    }
	    fprintf( f, "%02X ", c );
	}
    }
    if( in_string ){
        fputc( '"', f );
    }
    fputs( "\n", f );
    fflush( f );
}

static void callback( const struct mapipkt *pkt )
{
    dump_packet( stdout, &pkt->pkt, pkt->caplen );
}

int main( int argc, char **argv )
{
    int res;
    char *interface = "eth0";
    int errcode;

    int fd = mapi_create_flow( interface );
    //int fd = mapi_create_offline_flow( "tests/tracefile", MFF_PCAP );
    if( fd<0 ){
        fprintf( stderr, "Could not create a MAPI flow for interface `%s'\n", interface );
        mapi_read_error( &errcode, errstr );
        fprintf( stderr, "Error: %d: %s\n", errcode, errstr );
        exit( EXIT_FAILURE );
    }

    getcwd( filterpath, BUFSIZE );
    strcat( filterpath, "/filter.rl" );

    int sid = mapi_apply_function( fd, "RULER", filterpath );
    if( sid<0 ){
        fprintf( stderr, "Could not apply function RULER: error code %d\n", sid );
        mapi_read_error( &errcode, errstr );
        fprintf( stderr, "Error: %d: %s\n", errcode, errstr );
        exit( EXIT_FAILURE );
    }

    int bufid = mapi_apply_function( fd, "TO_BUFFER", WAIT );
    if( bufid<0 ){
        fprintf( stderr, "Could not apply function TO_BUFFER\n" );
        mapi_read_error( &errcode, errstr );
        fprintf( stderr, "Error: %d: %s\n", errcode, errstr );
        exit( EXIT_FAILURE );
    }

    res = mapi_connect( fd );
    if( res<0 ){
        fprintf( stderr, "Could not connect to flow %d\n", fd );
        exit( EXIT_FAILURE );
    }

    mapi_loop( fd, bufid, 50, &callback );

    mapi_close_flow( fd );

    return EXIT_SUCCESS;
}
