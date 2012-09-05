#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <syslog.h>
#include "debug.h"

#ifdef DEBUG

char *debug_message_file = NULL;	// filename information
int debug_message_line = 0;		// line number information
int log_level = LOGGING_DISABLED, log_to_syslog = 0, log_to_file = 0, log_fd_debug = -1;	// support for logging to file & syslog

void write_to_debug_file(int log_fd, char *msg, ...){

	char buf[STD_BUF];
	va_list ap;

	va_start(ap, msg);
	vsprintf(buf, msg, ap);
	write(log_fd, buf, strlen(buf));
	va_end(ap);

	return;
}

void debug_message(char *fmt, ...){
	
	char buf[STD_BUF + 1];
	va_list ap;
	int len;
	
	buf[STD_BUF] = '\0';

	va_start(ap, fmt);
	if(log_level == LOG_INFO_DEBUG_ALL || log_level == LOGGING_DISABLED){	// debug messages are printed to stdout and syslog OR logging to
										// syslog is disabled, thus debug messages are printed only to stdout
		vprintf(fmt, ap);
		
		if(debug_message_file != NULL)		// filename and line number information
			printf(" [%s:%d]\n", debug_message_file, debug_message_line);
	}

	va_end(ap);
	va_start(ap,fmt);
	if(log_level == LOG_INFO_DEBUG_NOT_STDOUT || log_level == LOG_INFO_DEBUG_ALL){	// print debug messages to syslog

		len = vsnprintf(buf, STD_BUF, fmt, ap);
		sprintf(buf + len, " [%s:%d]", debug_message_file, debug_message_line);	// filename and line number information
		buf[STD_BUF] = '\0';

		if(log_to_file)		write_to_debug_file(log_fd_debug, "%s\n", buf);
		if(log_to_syslog)	syslog(LOG_LOCAL1 | LOG_DEBUG, "%s", buf);
	}

	va_end(ap);
	return;
}

#else

void debug_message(MAPI_UNUSED char *fmt, ...){
}

void write_to_debug_file(MAPI_UNUSED int log_fd, MAPI_UNUSED char *msg, ...){
}

#endif	//DEBUG
