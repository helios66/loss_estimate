/* File: helper-functions.h
 *
 * Helper functions that are used by both the testing programs and the real
 * ruler launcher for MAPI.
 */

#include <sys/types.h>
#include <dirent.h>

#define TRACE_MAPI_CALLS 0
#define TRACE_COMPILATION 1

#define LIB_NAME "lib.so"

#define DIR_TEMPLATE "/tmp/ruler-XXXXXXXX"

typedef int process_packet_t( const unsigned char *packet, unsigned int len, unsigned char *outpacket, unsigned int *outlen );
typedef void initialise_t();

typedef struct str_instance_info {
    void *lib_handle;
    char *dir_name;
    char *lib_name;
    process_packet_t *processor;
} instance_info;

/* Given a printf format string 'fmt' and a list of argumemts 'args', return
 * the size of the resulting string.
 *
 * Only a subset of the general printf formatting is accepted.
 */
static size_t printf_len( const char *fmt, va_list args )
{
    const char *p = fmt;
    size_t sz = 0;

    while( *p != '\0' ){
	char c = *p++;

	if( c != '%' ){
	    sz++;
	    continue;
	}
	c = *p++;
	switch( c ){
	    case '%':
		sz += 1;
		break;

	    case 'c':
	    {
		// A char is promoted to an int when passed through '...'.
		const char arg = va_arg( args, int );

		(void) arg;
		sz += 1;
		break;
	    }

	    case 'd':
	    {
		int arg = va_arg( args, int );

		if( arg<0 ){
		    arg = -arg;
		    sz++;
		}
		if( arg == 0 ){
		    sz += 1;
		}
		while( arg>0 ){
		    sz++;
		    arg /= 10;
		}
		break;
	    }

	    case 'l':
	    {
		c = *p++;

		switch( c ){
		    case 'l':
		    {
			c = *p++;

			switch( c ){
			    case 'd':
			    {
				long long int arg = va_arg( args, long long int );

				if( arg<0 ){
				    arg = -arg;
				    sz++;
				}
				if( arg == 0 ){
				    sz += 1;
				}
				while( arg>0 ){
				    sz++;
				    arg /= 10;
				}
				break;
			    }

			    case 'u':
			    {
				unsigned long long int arg = va_arg( args, unsigned long long int );

				if( arg == 0 ){
				    sz += 1;
				}
				while( arg>0 ){
				    sz++;
				    arg /= 10;
				}
				break;
			    }

			    default:
				fprintf( stderr, "internal error: cannot determine length of formatted string `%s'\n", fmt );
                                exit( 1 );
			}
			break;
		    }

		    case 'd':
		    {
			long int arg = va_arg( args, long int );

			if( arg<0 ){
			    arg = -arg;
			    sz++;
			}
			if( arg == 0 ){
			    sz += 1;
			}
			while( arg>0 ){
			    sz++;
			    arg /= 10;
			}
			break;
		    }

		    case 'u':
		    {
			unsigned long int arg = va_arg( args, unsigned long int );

			if( arg == 0 ){
			    sz += 1;
			}
			while( arg>0 ){
			    sz++;
			    arg /= 10;
			}
			break;
		    }

		    default:
			fprintf( stderr, "internal error: cannot determine length of formatted string `%s'\n", fmt );
			exit( 1 );
		}
		break;
	    }

	    case 'u':
	    {
		unsigned int arg = va_arg( args, unsigned int );

		if( arg == 0 ){
		    sz += 1;
		}
		while( arg>0 ){
		    sz++;
		    arg /= 10;
		}
		break;
	    }

	    case 'x':
	    {
		unsigned int arg = va_arg( args, unsigned int );

		if( arg == 0 ){
		    sz += 1;
		}
		while( arg>0 ){
		    sz++;
		    arg /= 16;
		}
		break;
	    }

	    case 's':
	    {
		const char *arg = va_arg( args, char * );

		sz += strlen( arg );
		break;
	    }

	    default:
                fprintf( stderr, "internal error: cannot determine length of formatted string `%s'\n", fmt );
                exit( 1 );
	}
    }
    return sz;
}


static char *printf_string( const char *fmt, ... )
{
    va_list args;

    va_start( args, fmt );
    size_t sz = 1+printf_len( fmt, args );
    va_end( args );
    char *res = (char *) malloc( sz );
    if( res == NULL ){
        fputs( "Out of memory\n", stderr );
        exit( 1 );
    }
    va_start( args, fmt );
    (void) vsprintf( res, fmt, args );
    va_end( args );
    return res;
}

static char *create_temp_dir()
{
    char dirname[] = DIR_TEMPLATE;
    char *dnm = mkdtemp( dirname );
    if( dnm == NULL ){
        fprintf( stderr, "Cannot create temporary directory from template `%s'\n", dirname );
        return NULL;
    }
    return printf_string( "%s", dnm );
}

static void delete_directory( const char *name )
{
    DIR *dir;

    dir = opendir( name );
    if( dir == NULL ){
        if( errno == ENOENT ){
            return;
        }
        fprintf( stderr, "Cannot do opendir() on `%s': %s\n", name, strerror( errno ) );
        return;
    }
    for( ;; ){
        struct dirent *e = readdir( dir );

        if( e == NULL ){
            break;
        }
        if( strcmp( e->d_name, "." ) == 0 || strcmp( e->d_name, ".." ) == 0 ){
            continue;
        }
        char *fnm = printf_string( "%s/%s", name, e->d_name );
        unlink( fnm );
        free( fnm );
    }
    closedir( dir );
    rmdir( name );
}

static char *qualify_file( const char *fnm )
{
    char buf[PATH_MAX+1];

    char *p = getcwd( buf, PATH_MAX );
    if( p == NULL ){
        fprintf( stderr, "Cannot get current directory: %s\n", strerror( errno ) );
    }
    return printf_string( "%s/%s", buf, fnm );
}

static int run_command( const char *command )
{
    int res;

#if TRACE_COMPILATION
    fprintf( stderr, "Running compilation command `%s'\n", command );
#endif

    res = system( command );

#if TRACE_COMPILATION
    fprintf( stderr, "Compilation has finished, result code is %d\n", res );
#endif

    if( res == 127 ){
        fputs( "system() cannot execute shell\n", stderr );
        return 0;
    }
    if( res<0 ){
        fprintf( stderr, "Compilation command '%s' failed\n", command );
        return 0;
    }
    return 1;
}

static char *CC = "gcc";
static char *CFLAGS = "-O3 -W -Wall -shared -fPIC";
static char *RULER = "ruler";
static char *RULERFLAGS = "-T mapi-launcher.ct";


static int compile_filter( const char *dir_name, const char *lib_name, const char *source_name )
{
    char *command;
    int res;
    char *c_source = printf_string( "%s/src.c", dir_name );

    command = printf_string( "%s %s %s -o %s", RULER, RULERFLAGS, source_name, c_source );
    res = run_command( command );
    free( command );
    if( res == 0 ){
        return 0;
    }

    command = printf_string( "%s %s %s -o %s", CC, CFLAGS, c_source, lib_name );
    res = run_command( command );
    free( command );
    if( res == 0 ){
        return 0;
    }
    return 1;
}

/* Given the handle of a Ruler filter module, return the function pointer of
 * the packet processing function, or NULL if there is a problem.
 */
static initialise_t *get_init_function( void *handle )
{
    initialise_t *init;

    /* Now get hold of the function. */
    (void) dlerror();   /* As proscribed by the dlsym man page: clear errors. */
    init = dlsym( handle, "initialise" );
    char *err = dlerror(); /* Now see if there is an error. */
    if( err != NULL ){
        return NULL;
    }
#if TRACE_COMPILATION
    fprintf( stderr, "Address of initialise() is %p\n", init );
#endif
    return init;
}

/* Given the handle of a Ruler filter module, return the function pointer of
 * the packet processing function, or NULL if there is a problem.
 */
static process_packet_t *get_processor_function( void *handle )
{
    process_packet_t *processor;

    /* Now get hold of the function. */
    (void) dlerror();   /* As proscribed by the dlsym man page: clear errors. */
    processor = dlsym( handle, "process_packet" );
    char *err = dlerror(); /* Now see if there is an error. */
    if( err != NULL ){
        fprintf( stderr, "Can not get address of proccess_packet(): %s\n", err );
        return NULL;
    }
#if TRACE_COMPILATION
    fprintf( stderr, "Address of process_packet() is %p\n", processor );
#endif
    return processor;
}

/* Given a source file name, compile and load a new Ruler module to implement
 * this filter.
 */
static instance_info *create_ruler_filter( const char *source_file )
{
    instance_info *info;
    initialise_t *init;
    process_packet_t *processor;
    void *handle;
    char *dir_name;
    char *lib_name;

    /* Create a temporary directory to hold the compiled module. */
    dir_name = create_temp_dir();
    if( dir_name == NULL ){
        return NULL;
    }

    lib_name = printf_string( "%s/%s", dir_name, LIB_NAME );

    if( !compile_filter( dir_name, lib_name, source_file ) ){
        free( lib_name );
        free( dir_name );
        return NULL;
    }

#if TRACE_COMPILATION
    fprintf( stderr, "Compilation completed; opening library `%s'\n", lib_name );
#endif

    handle = dlopen( lib_name, RTLD_LAZY );
    if( handle == NULL ){
        fprintf( stderr, "Cannot open library `%s': %s\n", lib_name, dlerror() );
        free( lib_name );
        free( dir_name );
        return NULL;
    }

    init = get_init_function( handle );
    if( init != NULL ){
        (*init)();
    }

    processor = get_processor_function( handle );
    if( processor == NULL ){
        free( lib_name );
        free( dir_name );
        dlclose( handle );
        return NULL;
    }

    /* Create a structure to hold relevant info of this library. */
    info = (instance_info *) malloc( sizeof( instance_info ) );
    if( info == NULL ){
        fputs( "Out of memory", stderr );
        dlclose( handle );
        free( lib_name );
        free( dir_name );
        return NULL;
    }
    info->lib_handle = handle;
    info->processor = processor;
    info->dir_name = dir_name;
    info->lib_name = lib_name;
    return info;
}

/* Given the description of a loaded ruler filter, destroy it. */
static void destroy_ruler_filter( instance_info *info )
{
    int res = dlclose( info->lib_handle );
    if( res != 0 ){
        fprintf( stderr, "Cannot close library `%s': %s\n", info->lib_name, dlerror() );
    }

    delete_directory( info->dir_name );

    free( info->lib_name );
    free( info->dir_name );
    free( info );
}

