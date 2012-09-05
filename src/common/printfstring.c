#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
/* File: $Id: $ */

#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "printfstring.h"
#include "debug.h"

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
				DEBUG_CMD(Debug_Message("internal ERROR: cannot determine length of formatted string `%s'", fmt));
                                exit( EXIT_FAILURE );
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
			DEBUG_CMD(Debug_Message("internal ERROR: cannot determine length of formatted string `%s'", fmt));
			exit( EXIT_FAILURE );
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
                DEBUG_CMD(Debug_Message("internal ERROR: cannot determine length of formatted string `%s'", fmt));
                exit( EXIT_FAILURE );
	}
    }
    return sz;
}

char *printf_string( const char *fmt, ... )
{
    va_list args;
    size_t sz;
    char *res;

    va_start( args, fmt );
    sz = 1+printf_len( fmt, args );
    va_end( args );
    res = (char *) malloc( sz );
    if( res == NULL ){
        DEBUG_CMD(Debug_Message("ERROR: malloc failed - Out of memory"));
        exit( EXIT_FAILURE );
    }
    va_start( args, fmt );
    (void) vsprintf( res, fmt, args );
    va_end( args );
    return res;
}
