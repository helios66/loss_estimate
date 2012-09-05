#ifndef DEBUG_H
#define DEBUG_H

#define LOGGING_DISABLED		-1
#define LOG_INFORMATION			0
#define LOG_INFO_DEBUG_ALL		1
#define LOG_INFO_DEBUG_NOT_STDOUT	2

void debug_message(char *fmt, ...);
void write_to_debug_file(int log_fd, char *msg, ...);

#ifdef DEBUG

    extern char *debug_message_file;	// filename information
    extern int debug_message_line;	// line number information
    extern int log_level, log_to_syslog, log_to_file, log_fd_debug;

#define	Debug_Message	debug_message_file = __FILE__; debug_message_line = __LINE__; debug_message

#define DEBUG_CMD(code) code
#define STD_BUF 1024

#define ERROR_CMD(code) code	// leave them temporary here
#define WARNING_CMD(code) code
#define DEBUG_CMD2(code) code
#define DEBUG_CMD3(code) code

void debug_message(char *fmt, ...);
void write_to_debug_file(int log_fd, char *msg, ...);

#else

#define DEBUG_CMD(code)

#define ERROR_CMD(code)		// leave them temporary here
#define WARNING_CMD(code)
#define DEBUG_CMD2(code)
#define DEBUG_CMD3(code)

#if     __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ > 4)
#define MAPI_UNUSED                           \
  __attribute__((__unused__))
#else
#define MAPI_UNUSED
#endif

#endif	// DEBUG

#endif	// DEBUG_H
