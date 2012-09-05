#ifndef LOG_H
#define LOG_H

#include "mapi_remote.h"

#define LOGGING_DISABLED		-1
#define LOG_INFORMATION			0
#define LOG_INFO_DEBUG_ALL		1
#define LOG_INFO_DEBUG_NOT_STDOUT	2

#define STD_BUF 1024

int set_logging_to_file(char *mapi_conf, int *log_fd_info, int *log_fd_debug);
long acquire_write_lock(int log_fd);
void release_write_lock(int log_fd, long prev_file_size);
void write_newline(int log_fd, char *msg);
void write_to_file(int log_fd, char *msg, ...);
void write_date(int log_fd);
void write_libraries(int log_fd, char *path);
void daemon_started(int log_fd, char *daemon, char daemonize, int onlydevgroup);
void daemon_terminated(int log_fd, char *daemon, char daemonize, int onlydevgroup);

#ifdef DIMAPI
void mapicommd_logging(int log_to_file, int log_to_syslog, int log_fd, struct dmapiipcbuf *dbuf, ...);
#endif

int get_log_level(char *mapi_conf);
void open_syslog(int log_level, char *ident);
void log_message(char *msg, ...);
void syslog_libraries(char *path);

#endif	// LOG_H
