#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <syslog.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include "parseconf.h"
#include "mapiipc.h"
#include "mapi_remote.h"
#include "log.h"

/*
 * In order to log debug messages and general information messages to separate log files, syslog daemon must be configured as follows
 *
 * File /etc/syslog.conf should have the following two entries
 *  
 * local1.info;local1.!=debug				/var/tmp/info.syslog
 * local1.debug;local1.!=info				/var/tmp/debug.syslog
 *
 * /var/tmp/info.syslog & /var/tmp/debug.syslog are the names of the two files where debug and information messages are appended.
 * Thus, a MAPI user can change these filenames.
 *  
 * The /var/tmp/info.syslog & /var/tmp/debug.syslog files must exist before the syslogd daemon rereads the /etc/syslog.conf
 * configuration file, in order for the syslogd daemon to log messages to these files. To create these files, issue the following commands:
 *
 * touch /var/tmp/info.syslog
 * touch /var/tmp/debug.syslog
 *
 * Then issue the following command to force the syslogd daemon to reread its configuration file: kill -HUP <syslogd's process id>
 *
 * If a user wants support for logging to file, the filename is defined in mapi.conf in the logfile field.
 * For example, logfile=/usr/local/etc/mapi/mapi_logfile
 * 
 * Then, debug messages are printed to file /usr/local/etc/mapi/mapi_logfile.debug
 * and general information messages to file /usr/local/etc/mapi/mapi_logfile.info
 */

int set_logging_to_file(char *mapi_conf, int *log_fd_info, int *log_fd_debug){

	char *logfile, *logfile_info, *logfile_debug;
	int logging = 0;
  conf_category_t *conf;
	
	if((conf = pc_load(mapi_conf)) != NULL){
		
		logfile = pc_get_param(pc_get_category(conf, ""), "logfile");	// get logfile name
		
		if(logfile == NULL)		// no support for logging to file
			logging = 0;
		else{				// support for logging to file
			logfile_info = (char *)malloc(strlen(logfile) + 6);
			logfile_debug = (char *)malloc(strlen(logfile) + 7);

			strcpy(logfile_info, logfile);
			strcat(logfile_info, ".info");		// logfilename.info
			strcpy(logfile_debug, logfile);
			strcat(logfile_debug, ".debug");	// logfilename.debug

			logging = 1;

			*log_fd_info = open(logfile_info, O_WRONLY | O_CREAT | O_LARGEFILE | O_APPEND, S_IRUSR | S_IWUSR);
			
			if(*log_fd_info == -1){
				printf("Error in opening file: %s (%s)\n", logfile_info, strerror(errno));
				logging = 0;
			}

			*log_fd_debug = open(logfile_debug, O_WRONLY | O_CREAT | O_LARGEFILE | O_APPEND, S_IRUSR | S_IWUSR);
			
			if(*log_fd_debug == -1){
				printf("Error in opening file: %s (%s)\n", logfile_debug, strerror(errno));
				logging = 0;
			}

			free(logfile_info);
			free(logfile_debug);
		}
		if(logging)	printf("logging to file: enabled - LogFile: %s\n", logfile);
		else		printf("logging to file: disabled\n");

		pc_close(conf);
	}
	return logging;
}

long acquire_write_lock(int log_fd){

	struct flock fl;
	struct stat st;
	long file_size;

	fstat(log_fd, &st);		// stats the log file
	file_size = st.st_size;		// total size, in bytes
	
	fl.l_type = F_WRLCK;		// establish exclusive - write lock
	fl.l_whence = SEEK_SET;		// determines where the l_start field starts from
	fl.l_start = file_size;		// offset where the lock begins
	fl.l_len = 0;			// until EOF
	fl.l_pid = getpid();		// process holding the lock

	while( (fcntl(log_fd, F_SETLK, &fl) == -1))	// spinning ...	(already locked by another process)
		;

	return file_size;
}

void release_write_lock(int log_fd, long prev_file_size){

	struct flock fl;

	fl.l_type = F_UNLCK;		// remove write lock
	fl.l_whence = SEEK_SET;		// determines where the l_start field starts from
	fl.l_start = prev_file_size;	// offset where the lock begins
	fl.l_len = 0;			// until EOF
	fl.l_pid = getpid();		// process holding the lock
	
	fcntl(log_fd, F_SETLK, &fl);

	return;
}

void write_newline(int log_fd, char *msg){

	write(log_fd, msg, strlen(msg));
	return;
}

void write_to_file(int log_fd, char *msg, ...){

	char buf[STD_BUF];
	va_list ap;

	va_start(ap, msg);
	vsprintf(buf, msg, ap);
	write(log_fd, buf, strlen(buf));
	va_end(ap);

	return;
}

void write_date(int log_fd){
	
	struct timeval tv;
	time_t curtime;
	char *buffer, *buf, *s, str[10], *buffer_, *buf_;
	int count = 0, day, month, year;
	
	buffer = (char *)malloc(30 * sizeof(char));
	buf = (char *)malloc(30 * sizeof(char));

	buffer_ = buffer;
	buf_ = buf;

	gettimeofday(&tv, NULL);
	curtime = tv.tv_sec;		// number of seconds since the Epoch
	
	strftime(buffer, 30, "%m-%d-%Y %T.", localtime(&curtime));	// get time in specified format
	
	s = strchr(buffer, '.');
	*s = '\0';
	
	while( (s = strchr(buffer, '-')) != NULL){
		
		*s = '\0';
		
		if(count++ == 0)	sscanf(buffer, "%d", &month);
		else			sscanf(buffer, "%d", &day);
		
		buffer = s + 1;
	}

	sscanf(buffer, "%d", &year);
	s = strchr(buffer, ' ');
	buffer = s + 1;
	
	*buf = '\0';
	sprintf(str, "%d", day);
	buf = strcat(buf, str);
	buf = strcat(buf, "/");
	sprintf(str, "%d", month);
	buf = strcat(buf, str);
	buf = strcat(buf, "/");
	sprintf(str, "%d", year);
	buf = strcat(buf, str);
	buf = strcat(buf, " ");
	buf = strcat(buf, buffer);

	write_to_file(log_fd, "%s", buf);

	free(buffer_);
	free(buf_);

	return;
}

void write_libraries(int log_fd, char *path){

	char *s, *s_;

	while( (s = strchr(path, ':')) != NULL){
		
		*s = '\0';
		s_ = strchr(path, '.');
		*s_ = '\0';

		write_to_file(log_fd, "Library %s loaded\n", path);
		path = s + 1;
	}

	s_ = strchr(path, '.');
	*s_ = '\0';

	write_to_file(log_fd, "Library %s loaded\n\n", path);
	return;
}

void daemon_started(int log_fd, char *daemon, char daemonize, int onlydevgroup){

	long file_size;
	
	file_size = acquire_write_lock(log_fd);
	write_to_file(log_fd, "\t\t\t%s was started at ", daemon);
	write_date(log_fd);
	
	if(daemonize)		write_to_file(log_fd, " ( is running as daemon )");
	if(onlydevgroup)	write_to_file(log_fd, " - ( is binding limited set of devices (aka devgroup) )");

	write_newline(log_fd, "\n\n");

	if(strcmp(daemon, "MAPICOMMD") == 0){
#ifdef DIMAPISSL
		write_to_file(log_fd, "SSL enabled\n");
#endif
	}

	release_write_lock(log_fd, file_size);
	return;
}

void daemon_terminated(int log_fd, char *daemon, char daemonize, int onlydevgroup){

	long file_size;
	
	file_size = acquire_write_lock(log_fd);
	write_to_file(log_fd, "\n\t\t\t%s was terminated at ", daemon);
	write_date(log_fd);
	
	if(daemonize)		write_to_file(log_fd, " ( was running as daemon )");
	if(onlydevgroup)	write_to_file(log_fd, " - ( was binding limited set of devices (aka devgroup) )");

	write_newline(log_fd, "\n\n");
	release_write_lock(log_fd, file_size);
	close(log_fd);

	return;
}

/* log_level = 0 ---> Log only general information and not debugging messages
 * log_level = 1 ---> Log general information plus debugging information (debug messages are printed to stdout, syslog and logfile)
 * log_level = 2 ---> Log general information plus debugging information (debug messages are printed to syslog and logfile)
 * 
 * For all the above log levels, debug and/or info messages are printed to syslog and logfile,
 * if logging to syslog is enabled and logging to file is enabled, respectively.
 *
 * The default level is 2
 */
int get_log_level(char *mapi_conf){

	int log_level = LOGGING_DISABLED;
  conf_category_t *conf;

	if((conf = pc_load(mapi_conf)) != NULL){
		char *log_level_str = pc_get_param(pc_get_category(conf, ""), "log_level");

		if (log_level_str != NULL) {
			log_level = atoi(log_level_str);
			if(log_level == 0)	log_level = LOG_INFORMATION;
			else if(log_level == 1)	log_level = LOG_INFO_DEBUG_ALL;
			else if(log_level == 2)	log_level = LOG_INFO_DEBUG_NOT_STDOUT;
			else			log_level = LOG_INFO_DEBUG_NOT_STDOUT;	// default level
		} else {
			log_level = LOG_INFO_DEBUG_NOT_STDOUT;	// default level
		}

		pc_close (conf);
	}
	return log_level;
}

void open_syslog(int log_level, char *ident){

	if(log_level == LOG_INFORMATION){

		setlogmask(LOG_MASK(LOG_INFO));
		openlog(ident, LOG_CONS | LOG_NDELAY, LOG_LOCAL1);
	}

	else if(log_level == LOG_INFO_DEBUG_ALL || log_level == LOG_INFO_DEBUG_NOT_STDOUT){

		setlogmask(LOG_MASK(LOG_DEBUG) | LOG_MASK(LOG_INFO));
		openlog(ident, LOG_CONS | LOG_NDELAY, LOG_LOCAL1);
	}

	return;
}

void log_message(char *msg, ...){

	char buf[STD_BUF + 1];
	va_list ap;

	buf[STD_BUF] = '\0';

	va_start(ap, msg);
	vsnprintf(buf, STD_BUF, msg, ap);

	buf[STD_BUF] = '\0';
	syslog(LOG_LOCAL1 | LOG_INFO, "%s", buf);
	
	va_end(ap);
	return;
}

void syslog_libraries(char *path){

	char *s, *s_;

	while( (s = strchr(path, ':')) != NULL){
		
		*s = '\0';
		s_ = strchr(path, '.');
		*s_ = '\0';

		log_message("Library %s loaded", path);
		path = s + 1;
	}

	s_ = strchr(path, '.');
	*s_ = '\0';

	log_message("Library %s loaded", path);
	return;
}

#ifdef DIMAPI
void mapicommd_logging(int log_to_file, int log_to_syslog, int log_fd, struct dmapiipcbuf *dbuf, ...){

	int mapid_result;
	long file_size;
	va_list ap;

	va_start(ap, dbuf);
	mapid_result = va_arg(ap, int);
	va_end(ap);

	switch(dbuf->cmd){

		case CREATE_FLOW:
			if(log_to_file){
				file_size = acquire_write_lock(log_fd);
				write_to_file(log_fd, "MAPICOMMD: create flow (device: %s, fd: %d) %s at ",
										dbuf->data, mapid_result, mapid_result < 0 ? "FAILED" : "OK");
				write_date(log_fd); write_newline(log_fd, "\n");
				release_write_lock(log_fd, file_size);
			}
			if(log_to_syslog)
				log_message("create flow (device: %s, fd: %d) %s", dbuf->data, mapid_result, mapid_result < 0 ? "FAILED" : "OK");
			break;

		case CLOSE_FLOW:
			if(log_to_file){
				file_size = acquire_write_lock(log_fd);
				write_to_file(log_fd, "MAPICOMMD: close flow (fd: %d) %s at ", dbuf->fd, mapid_result == 0 ? "OK" : "FAILED");
				write_date(log_fd); write_newline(log_fd, "\n");
				release_write_lock(log_fd, file_size);
			}
			if(log_to_syslog)
				log_message("close flow (fd: %d) %s", dbuf->fd, mapid_result == 0 ? "OK" : "FAILED");
			break;

		case CONNECT:
			if(log_to_file){
				file_size = acquire_write_lock(log_fd);
				write_to_file(log_fd, "MAPICOMMD: connect to flow (fd: %d) %s at ", dbuf->fd, mapid_result >= 0 ? "OK" : "FAILED");
				write_date(log_fd); write_newline(log_fd, "\n");
				release_write_lock(log_fd, file_size);
			}
			if(log_to_syslog)
				log_message("connect to flow (fd: %d) %s", dbuf->fd, mapid_result >= 0 ? "OK" : "FAILED");
			break;

		case APPLY_FUNCTION:
			if(log_to_file){
				file_size = acquire_write_lock(log_fd);
				write_to_file(log_fd, "MAPICOMMD: apply function %s (fid: %d) %s at ",
							dbuf->data, dbuf->fid, mapid_result == 0 ? "OK" : "FAILED");
				write_date(log_fd); write_newline(log_fd, "\n");
				release_write_lock(log_fd, file_size);
			}
			if(log_to_syslog)
				log_message("apply function %s (fid: %d) %s", dbuf->data, dbuf->fid, mapid_result == 0 ? "OK" : "FAILED");
			break;

		case READ_RESULT:
			if(log_to_file){
				file_size = acquire_write_lock(log_fd);
				write_to_file(log_fd, "MAPICOMMD: read results (fd: %d, fid: %d) FAILED at ", dbuf->fd, dbuf->fid);
				write_date(log_fd); write_newline(log_fd, "\n");
				release_write_lock(log_fd, file_size);
			}
			if(log_to_syslog)
				log_message("read results (fd: %d, fid: %d) FAILED", dbuf->fd, dbuf->fid);
			break;

		case GET_FLOW_INFO:
		case GET_NEXT_FLOW_INFO:
			if(log_to_file){
				file_size = acquire_write_lock(log_fd);
				write_to_file(log_fd, "MAPICOMMD: get %s info (fd: %d) %s at ",
						dbuf->cmd == GET_FLOW_INFO ? "flow" : "next flow", dbuf->fd, mapid_result == 0 ? "OK" : "FAILED");
				write_date(log_fd); write_newline(log_fd, "\n");
				release_write_lock(log_fd, file_size);
			}
			if(log_to_syslog)
				log_message("get %s info (fd: %d) %s",
						dbuf->cmd == GET_FLOW_INFO ? "flow" : "next flow", dbuf->fd, mapid_result == 0 ? "OK" : "FAILED");
			break;

		case GET_DEVICE_INFO:
		case GET_NEXT_DEVICE_INFO:
			if(log_to_file){
				file_size = acquire_write_lock(log_fd);
				write_to_file(log_fd, "MAPICOMMD: get %s info (fd: %d) %s at ",
						dbuf->cmd == GET_DEVICE_INFO ? "device" : "next device", dbuf->fd, mapid_result == 0 ? "OK" : "FAILED");
				write_date(log_fd); write_newline(log_fd, "\n");
				release_write_lock(log_fd, file_size);
			}
			if(log_to_syslog)
				log_message("get %s info (fd: %d) %s",
						dbuf->cmd == GET_DEVICE_INFO ? "device" : "next device", dbuf->fd, mapid_result == 0 ? "OK" : "FAILED");
			break;

		case GET_FUNCTION_INFO:
		case GET_NEXT_FUNCTION_INFO:
			if(log_to_file){
				file_size = acquire_write_lock(log_fd);
				write_to_file(log_fd, "MAPICOMMD: get %s info (fd: %d, fid: %d) %s at ",
							dbuf->cmd == GET_FUNCTION_INFO ? "function" : "next function", dbuf->fd, dbuf->fid,
							mapid_result == 0 ? "OK" : "FAILED");
				write_date(log_fd); write_newline(log_fd, "\n");
				release_write_lock(log_fd, file_size);
			}
			if(log_to_syslog)
				log_message("get %s info (fd: %d, fid: %d) %s", dbuf->cmd == GET_FUNCTION_INFO ? "function" : "next function",
							dbuf->fd, dbuf->fid, mapid_result == 0 ? "OK" : "FAILED");
			break;

#ifdef WITH_AUTHENTICATION
		case AUTHENTICATE:
			if(log_to_file){
				file_size = acquire_write_lock(log_fd);
				write_to_file(log_fd, "MAPICOMMD: authenticate flow (fd: %d) %s at ", dbuf->fd, mapid_result == 0 ? "OK" : "FAILED");
				write_date(log_fd); write_newline(log_fd, "\n");
				release_write_lock(log_fd, file_size);
			}
			if(log_to_syslog)
				log_message("authenticate flow (fd: %d) %s", dbuf->fd, mapid_result == 0 ? "OK" : "FAILED");
			break;
#endif
		case MAPI_STATS:
			if(log_to_file){
				file_size = acquire_write_lock(log_fd);
				write_to_file(log_fd, "MAPICOMMD: mapi stats (device: %s) %s at ", dbuf->data, mapid_result < 0 ? "FAILED" : "OK");
				write_date(log_fd); write_newline(log_fd, "\n");
				release_write_lock(log_fd, file_size);
			}
			if(log_to_syslog)
				log_message("mapi stats (device: %s) %s", dbuf->data, mapid_result < 0 ? "FAILED" : "OK");
			break;

		default:
			break;
	}
	
	return;
}
#endif
