#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <pthread.h>
#include <signal.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <errno.h>
#include <fcntl.h>
#include "mapi.h"
#include "mapi_remote.h"
#include "mapi_internal.h"
#include "mapiipc.h"
#include "parseconf.h"
#include "mapi_errors.h"
#include "mapilibhandler.h"
#include "printfstring.h"
#include "debug.h"
#include "log.h"

#define MAXPENDING 500    /* Maximum outstanding connection requests */

int service_count;
int dimapi_port;

int log_fd_info = -1;	// support for logging to file

static char daemonize = 0;

#ifdef DIMAPISSL
struct overload *inst = NULL;
SSL_CTX *ctx;
#endif

extern void set_agent();
void *handle_request(void *);
int die(char *msg);
int getfid(struct dmapiipcbuf *dbuf);
void mapicommd_shutdown(int exit_value);

static void print_usage (const char *name) {
	printf ("Usage: %s [OPTIONS]\n", name);
	printf("  -d, --daemon		Run as daemon\n");
	printf("  -s, --syslog		Logging to syslog\n");
	printf("  -h, --help		Display this message\n");
}

static void parse_arguments (int argc, char **argv) {

	int c;
	static const char optstring[] = "dhs";
	static const struct option longopts[] = {
		{"daemon", no_argument, NULL, 'd'},
		{"syslog", no_argument, NULL, 's'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	while ((c = getopt_long (argc, argv, optstring, longopts, NULL)) != -1) {
		switch (c) {
			case 'd':
				daemonize = 1;
				break;
			case 's':	// logging to syslog enabled
				log_to_syslog = 1;
				break;
			case 'h':
			case '?':
			default:
				print_usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}
}

static int continue_as_daemon() {
	int nullfd;

	printf("Closing stdin, stdout, stderr and going into background.\n");

	switch(fork()) {
		case 0: 
			break;
		case -1:
			DEBUG_CMD(Debug_Message("ERROR: fork() failed %d - %s", errno, strerror(errno)));
			return EXIT_FAILURE;
			break;
		default:
			_exit(0);
			break;
	}
	if(setsid() == -1) {
		DEBUG_CMD(Debug_Message("ERROR: setsid() failed %d - %s", errno, strerror(errno)));
		return EXIT_FAILURE;
	}

	setpgrp();

	switch(fork()) {
		case 0: 
			break;
		case -1:
			DEBUG_CMD(Debug_Message("ERROR: fork() failed %d - %s", errno, strerror(errno)));
			return EXIT_FAILURE;
			break;
		default:
			_exit(0);
			break;
	}
	
	chdir("/");

	nullfd = open("/dev/null", O_RDONLY);
	dup2(nullfd, STDIN_FILENO);
	close(nullfd);
	nullfd = open("/dev/null", O_WRONLY);
	dup2(nullfd, STDOUT_FILENO);
	dup2(nullfd, STDERR_FILENO);
	close(nullfd);
	
	return EXIT_SUCCESS;
}

int main (int argc, char *argv[]){

	int serv_sock = 0;
	int new_sock = 0;      /* client's socket descriptor (from connect()) */
	socklen_t clnt_len;    /* length of client address data structure */
	int yes=1;
	char* mapi_conf;
	long file_size;
	pthread_t chld_thr;
	struct sockaddr_in serv_addr;
	struct sockaddr_in clnt_addr;
  conf_category_t *conf;

	parse_arguments (argc, argv);

#ifdef DIMAPISSL
	SSL *con = NULL;
	OpenSSL_add_all_algorithms();	// adds all algorithms to the table (digests and ciphers)
					// OpenSSL keeps an internal table of digest algorithms and ciphers
	SSL_library_init();		// registers the available ciphers and digests
	SSL_load_error_strings();	// registers the error strings for all libcrypto functions and libssl
#endif

	signal (SIGTERM, mapicommd_shutdown);
	signal (SIGQUIT, mapicommd_shutdown);
	signal (SIGINT, mapicommd_shutdown);

	mapi_conf = printf_string( CONFDIR"/"CONF_FILE );

	printf("using %s\n", mapi_conf);
#ifdef DIMAPISSL
	printf("SSL enabled\n");
#endif
	log_level = get_log_level(mapi_conf);	// get log level from mapi.conf	

	if(log_to_syslog)	// logging to syslog is enabled
		open_syslog(log_level, "MAPICOMMD");
	
	log_to_file = set_logging_to_file(mapi_conf, &log_fd_info, &log_fd_debug);	// support for logging to file
	
	if(log_to_syslog == 0 && log_to_file == 0)
		log_level = LOGGING_DISABLED;

	if((conf = pc_load (mapi_conf)) != NULL)
		dimapi_port = atoi(pc_get_param(pc_get_category(conf, ""), "dimapi_port"));
	else{
		printf("Error: cannot load mapi.conf file.\n");
		mapicommd_shutdown(1);
	}
	free(mapi_conf);
	pc_close(conf);

	if(log_to_syslog == 0)	printf("logging to syslog: disabled\n");
	else			printf("logging to syslog: enabled - LogLevel: %d\n", log_level);

	if(log_to_file){
		daemon_started(log_fd_info, "MAPICOMMD", daemonize, 0);
		daemon_started(log_fd_debug, "MAPICOMMD", daemonize, 0);
	}
	
	if(log_to_syslog){
		log_message("MAPICOMMD was started %s", daemonize ? " ( is running as daemon )" : "");
#ifdef DIMAPISSL
		log_message("SSL enabled");
#endif
	}

	if ((serv_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		die("Unexpected error on socket()");
		mapicommd_shutdown(-1);
	}

	memset(&serv_addr, 0, sizeof serv_addr);

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(dimapi_port);

#ifdef DIMAPISSL
	if ((ctx=SSL_CTX_new(SSLv3_server_method())) == NULL) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	if (SSL_CTX_use_certificate_file(ctx, CONFDIR"/"MAPICOMMD_SSL_CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, CONFDIR"/"MAPICOMMD_SSL_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
#endif

	/* DANGEROUS, but useful for debugging, so leave it for now */
	if (setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		close(serv_sock);
		die("Unexpected error on setsockopt()");
	}

	if (bind(serv_sock, (struct sockaddr *)&serv_addr, sizeof serv_addr) == -1) {
		close(serv_sock);
		die("Unexpected error on bind()");
		mapicommd_shutdown(-1);
	}

	/* queue max 5 connections */
	if (listen(serv_sock, MAXPENDING) == -1) {
		shutdown(serv_sock, SHUT_RDWR);
		close(serv_sock);
		die("Unexpected error on listen()");
		mapicommd_shutdown(-1);
	}

	set_agent();

	if(daemonize) continue_as_daemon();

	while(1) {

		clnt_len = sizeof clnt_addr;
		if ((new_sock = accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_len)) == -1) {
			die("Unexpected error on accept()");
			continue;
		}

#ifdef DIMAPISSL
		if ((con=SSL_new(ctx)) == NULL) {
			ERR_print_errors_fp(stderr);
			continue;
		}
		if (SSL_set_fd(con, new_sock) == 0) {
			ERR_print_errors_fp(stderr);
			continue;
		}
		if (SSL_accept(con) <= 0) {
			ERR_print_errors_fp(stderr);
			continue;
		}
#endif
		printf("<*> got connection from %s\n", inet_ntoa(clnt_addr.sin_addr));

		if(log_to_file){
			file_size = acquire_write_lock(log_fd_info);
			write_to_file(log_fd_info, "MAPICOMMD: mapicommd got connection from * %s * at ", inet_ntoa(clnt_addr.sin_addr));
			write_date(log_fd_info);
			write_newline(log_fd_info, "\n");
			release_write_lock(log_fd_info, file_size);
		}
		if(log_to_syslog)
			log_message("mapicommd got connection from * %s *", inet_ntoa(clnt_addr.sin_addr));
#ifdef DIMAPISSL
		inst = (struct overload *)malloc(sizeof(struct overload));
		inst->connection = con;
		inst->sock = new_sock;

		if (pthread_create(&chld_thr, NULL, handle_request, (void *) inst) != 0){
			die("pthread_create() failed");
			continue;
		}
#else
		if (pthread_create(&chld_thr, NULL, handle_request, (void *) &new_sock) != 0) {
			die("pthread_create() failed");
			continue;
		}
#endif
	} /* while (1) */
	return 0; /* never reached */
}

void *handle_request(void *arg) {
#ifdef DIMAPISSL
	SSL *con = ((struct overload*)arg)->connection;
	int sock = ((struct overload*)arg)->sock;
#else
	int sock = *(int *)arg;
#endif
	int recv_bytes;
	struct dmapiipcbuf *dbuf=NULL;
	int mapid_result;
	mapi_results_t *result;
	int i;
	int *active_flows = NULL;
	int ac_fl_size=0;
	mapi_function_info_t funct_info;
	mapi_flow_info_t flow_info;
	mapi_device_info_t device_info;
	struct timeval tv; /*used for timestamping results when produced */
	struct mapipkt *pkt;
	int errno;
	char errorstr[MAPI_ERRORSTR_LENGTH], str[30];
	long file_size;
	struct mapi_stat stats;
	char* dev;
	char *devtype = NULL;
#ifdef RECONNECT
	int flag = 0;
#endif

	/* Guarantees that thread resources are deallocated upon return */
	pthread_detach(pthread_self());
	dbuf = (struct dmapiipcbuf *)malloc(sizeof(struct dmapiipcbuf));

#ifdef DIMAPISSL
	DEBUG_CMD(Debug_Message("<+> new thread %lu, socket number = %d", pthread_self(),(int) con));
	sprintf(str, "%d", (int) con);

	if(inst != NULL){
		free(inst);
		inst = NULL;
	}
#else
	DEBUG_CMD(Debug_Message("<+> new thread %lu, socket number = %d", pthread_self(), sock));
	sprintf(str, "%d", sock);
#endif
	if(log_to_file){
		file_size = acquire_write_lock(log_fd_info);
		write_to_file(log_fd_info, "MAPICOMMD: new thread %lu, socket number %s\n\n", pthread_self(), str);
		release_write_lock(log_fd_info, file_size);
	}

	while(1) {

#ifdef DIMAPISSL
		recv_bytes = SSL_readn(con,dbuf,BASIC_SIZE);
#else
		recv_bytes=readn(sock, dbuf, BASIC_SIZE);
#endif
		if (recv_bytes == 0) { // the peer has gone
			DEBUG_CMD(Debug_Message("Peer has gone"));

			if(log_to_file){
				file_size = acquire_write_lock(log_fd_info);
				write_to_file(log_fd_info, "MAPICOMMD: Peer has gone at ");
				write_date(log_fd_info);
				write_newline(log_fd_info, "\n");
				release_write_lock(log_fd_info, file_size);
			}
			break;
		}
		else if (recv_bytes == -1) {
			die("recv()");
			break;
		}

		if (dbuf->length > DIMAPI_DATA_SIZE) {
			DEBUG_CMD(Debug_Message("WARNING: Ignoring invalid message"));
			
			if(log_to_file){
				file_size = acquire_write_lock(log_fd_info);
				write_to_file(log_fd_info, "MAPICOMMD: Warning - Ignoring invalid message\n");
				release_write_lock(log_fd_info, file_size);
			}
			continue;
		}

		if (dbuf->length-BASIC_SIZE>0) {
#ifdef DIMAPISSL
			recv_bytes = SSL_readn(con,(char *)dbuf+BASIC_SIZE,dbuf->length-BASIC_SIZE);
#else
			recv_bytes=readn(sock, (char*)dbuf+BASIC_SIZE, dbuf->length-BASIC_SIZE);
#endif
			if (recv_bytes == 0) { // the peer has gone
				DEBUG_CMD(Debug_Message("Peer has gone"));

				if(log_to_file){
					file_size = acquire_write_lock(log_fd_info);
					write_to_file(log_fd_info, "MAPICOMMD: Peer has gone at ");
					write_date(log_fd_info);
					write_newline(log_fd_info, "\n");
					release_write_lock(log_fd_info, file_size);
				}
				break;
			}
			else if (recv_bytes == -1) {
				die("recv()");
				break;
			}
		}
#ifdef RECONNECT

		if(dbuf->cmd == IGNORE_SLEEP){	// ignore some messages
			flag = 1;
			continue;
		}

		if(dbuf->cmd == IGNORE_NOTIFY){	// accept all kind of messages
			flag = 0;
			continue;
		}

		if(dbuf->cmd != CREATE_FLOW && dbuf->cmd != APPLY_FUNCTION && dbuf->cmd != CONNECT && dbuf->cmd != AUTHENTICATE && flag == 1)
			continue;
#endif
		switch(dbuf->cmd) {
			case CREATE_FLOW:
				mapid_result = mapi_create_flow(dbuf->data);
				fprintf(stdout,"CREATE_FLOW (%s, %d)\n",dbuf->data, mapid_result);
				mapicommd_logging(log_to_file, log_to_syslog, log_fd_info, dbuf, mapid_result);
				if(mapid_result <0) {
					dbuf->cmd = ERROR_ACK;
					mapi_read_error(&errno, errorstr);
					memcpy(dbuf->data, &errno, sizeof(int));
				}
				else {
					devtype = mapi_get_devtype_of_flow(mapid_result);
					if(devtype != NULL) {
					dbuf->cmd = CREATE_FLOW_ACK;
					memcpy(dbuf->data, &mapid_result, sizeof(int));
					memcpy(((char *)dbuf->data) + sizeof(int), devtype, strlen(devtype)+1);
					active_flows = realloc(active_flows,(ac_fl_size+1)*sizeof(int));
					active_flows[ac_fl_size++] = mapid_result;
				}
				else {
					dbuf->cmd = ERROR_ACK;
					mapi_read_error(&errno, errorstr);
					memcpy(dbuf->data, &errno, sizeof(int));
				}
				}
				dbuf->length = BASIC_SIZE+sizeof(int)+strlen(devtype)+1;
				break;
			case CLOSE_FLOW:
				fprintf(stdout,"CLOSE_FLOW (%d)\n",dbuf->fd);
				mapid_result = mapi_close_flow(dbuf->fd);
				mapicommd_logging(log_to_file, log_to_syslog, log_fd_info, dbuf, mapid_result);
				if(!mapid_result){
					for(i=0;i<ac_fl_size;++i){
						if(active_flows[i] == dbuf->fd){
							active_flows[i] = active_flows[--ac_fl_size];
							active_flows = realloc(active_flows,ac_fl_size*sizeof(int));
						}
					}
				}
				//no need to send responce
				break;
			case CONNECT:
				fprintf(stdout,"CONNECT (%d)",dbuf->fd);
				mapid_result = mapi_connect(dbuf->fd);
				mapicommd_logging(log_to_file, log_to_syslog, log_fd_info, dbuf, mapid_result);
				if(mapid_result >= 0){
					dbuf->cmd = CONNECT_ACK;
					fprintf(stdout," OK\n");
					dbuf->length = BASIC_SIZE;
				}
				else{
					dbuf->cmd = ERROR_ACK;
					mapi_read_error(&errno, errorstr);
					memcpy(dbuf->data, &errno, sizeof(int));
					fprintf(stdout," FAILED\n");
					dbuf->length = BASIC_SIZE+sizeof(int);
				}
				break;
			case APPLY_FUNCTION:
				fprintf(stdout,"APPLY_FUNCTION\n");
				if((( dbuf->fid = getfid(dbuf))!=-1)){
					mapicommd_logging(log_to_file, log_to_syslog, log_fd_info, dbuf, 0);
					dbuf->cmd = APPLY_FUNCTION_ACK;
					dbuf->length = BASIC_SIZE;
				}
				else{
					mapicommd_logging(log_to_file, log_to_syslog, log_fd_info, dbuf, -1);
					dbuf->cmd = ERROR_ACK;
					mapi_read_error(&errno, errorstr);
					memcpy(dbuf->data, &errno, sizeof(int));
					dbuf->length = BASIC_SIZE+sizeof(int);
				}
				break;
			case READ_RESULT:
				result = mapi_read_results(dbuf->fd,dbuf->fid);
				if(result!=NULL && result->size < DIMAPI_DATA_SIZE){
					dbuf->cmd = READ_RESULT_ACK;
					dbuf->timestamp = result->ts;
					memcpy(dbuf->data, result->res, result->size);
					dbuf->length = BASIC_SIZE + result->size;
				}
				else{
					fprintf(stdout,"mapi_read_results failed...\n");
					mapicommd_logging(log_to_file, log_to_syslog, log_fd_info, dbuf, -1);
					dbuf->cmd = ERROR_ACK;
					mapi_read_error(&errno, errorstr);
					memcpy(dbuf->data, &errno, sizeof(int));
					dbuf->length = BASIC_SIZE+sizeof(int);
				}
				break;
			case GET_NEXT_PKT:
				pkt = (struct mapipkt *)mapi_get_next_pkt(dbuf->fd,dbuf->fid);
				gettimeofday(&tv, NULL);
				dbuf->timestamp = tv.tv_usec;
				if(pkt!=NULL){
					dbuf->cmd = GET_NEXT_PKT_ACK;
					memcpy(dbuf->data, pkt, sizeof(struct mapipkt)-4+pkt->caplen);
					dbuf->length = BASIC_SIZE + sizeof(struct mapipkt) - 4 + pkt->caplen;
				}
				else{
					dbuf->cmd = GET_NEXT_PKT_ACK;
					dbuf->length = BASIC_SIZE;
				}
				break;
			case GET_FLOW_INFO:
				fprintf(stdout,"GET_FLOW_INFO\n");
				if(mapi_get_flow_info(dbuf->fd, &flow_info)){
					mapicommd_logging(log_to_file, log_to_syslog, log_fd_info, dbuf, -1);
					dbuf->cmd = MAPI_FLOW_INFO_ERR;
					dbuf->length = BASIC_SIZE;
				}
				else{
					mapicommd_logging(log_to_file, log_to_syslog, log_fd_info, dbuf, 0);
					dbuf->cmd = GET_FLOW_INFO_ACK;
					memcpy(dbuf->data,&flow_info,sizeof(mapi_flow_info_t));
					dbuf->length = BASIC_SIZE+sizeof(mapi_flow_info_t);
				}
				break;
			case GET_NEXT_FLOW_INFO:
				fprintf(stdout,"GET_NEXT_FLOW_INFO\n");
				if(mapi_get_next_flow_info(dbuf->fd, &flow_info)){
					mapicommd_logging(log_to_file, log_to_syslog, log_fd_info, dbuf, -1);
					dbuf->cmd = MAPI_FLOW_INFO_ERR;
					dbuf->length = BASIC_SIZE;
				}
				else{
					mapicommd_logging(log_to_file, log_to_syslog, log_fd_info, dbuf, 0);
					dbuf->cmd = GET_FLOW_INFO_ACK;
					memcpy(dbuf->data,&flow_info,sizeof(mapi_flow_info_t));
					dbuf->length = BASIC_SIZE+sizeof(mapi_flow_info_t);
				}
				break;
			case GET_DEVICE_INFO:
				fprintf(stdout,"GET_DEVICE_INFO\n");
				if(mapi_get_flow_info(dbuf->fd, &flow_info)){
					mapicommd_logging(log_to_file, log_to_syslog, log_fd_info, dbuf, -1);
					dbuf->cmd = GET_DEVICE_INFO_NACK;
					dbuf->length = BASIC_SIZE;
				}

				if(mapi_get_device_info(flow_info.devid, &device_info)<0){
					mapicommd_logging(log_to_file, log_to_syslog, log_fd_info, dbuf, -1);
					dbuf->cmd = GET_DEVICE_INFO_NACK;
					dbuf->length = BASIC_SIZE;
				}
				else{
					mapicommd_logging(log_to_file, log_to_syslog, log_fd_info, dbuf, 0);
					dbuf->cmd = GET_DEVICE_INFO_ACK;
					memcpy(dbuf->data,&device_info,sizeof(mapi_device_info_t));
					dbuf->length = BASIC_SIZE+sizeof(mapi_device_info_t);
				}
				break;
			case GET_NEXT_DEVICE_INFO:
				fprintf(stdout,"GET_NEXT_DEVICE_INFO\n");
				if(mapi_get_flow_info(dbuf->fd, &flow_info)){
					mapicommd_logging(log_to_file, log_to_syslog, log_fd_info, dbuf, -1);
					dbuf->cmd = GET_DEVICE_INFO_NACK;
					dbuf->length = BASIC_SIZE;
				}

				if(mapi_get_next_device_info(flow_info.devid, &device_info)<0){
					mapicommd_logging(log_to_file, log_to_syslog, log_fd_info, dbuf, -1);
					dbuf->cmd = GET_DEVICE_INFO_NACK;
					dbuf->length = BASIC_SIZE;
				}
				else{
					mapicommd_logging(log_to_file, log_to_syslog, log_fd_info, dbuf, 0);
					dbuf->cmd = GET_DEVICE_INFO_ACK;
					memcpy(dbuf->data,&device_info,sizeof(mapi_device_info_t));
					dbuf->length = BASIC_SIZE+sizeof(mapi_device_info_t);
				}
				break;
			case GET_FUNCTION_INFO:
				fprintf(stdout,"GET_FUNCTION_INFO\n");
				if(mapi_get_function_info(dbuf->fd, dbuf->fid, &funct_info)){
					mapicommd_logging(log_to_file, log_to_syslog, log_fd_info, dbuf, -1);
					dbuf->cmd = MAPI_FUNCTION_INFO_ERR;
					dbuf->length = BASIC_SIZE;
				}
				else{
					mapicommd_logging(log_to_file, log_to_syslog, log_fd_info, dbuf, 0);
					dbuf->cmd = GET_FUNCTION_INFO_ACK;
					memcpy(dbuf->data,&funct_info,sizeof(mapi_function_info_t));
					dbuf->length = BASIC_SIZE+sizeof(mapi_function_info_t);
				}
				break;
			case GET_NEXT_FUNCTION_INFO:
				fprintf(stdout,"GET_NEXT_FUNCTION_INFO\n");
				if(mapi_get_next_function_info(dbuf->fd, dbuf->fid, &funct_info)){
					mapicommd_logging(log_to_file, log_to_syslog, log_fd_info, dbuf, -1);
					dbuf->cmd = MAPI_FUNCTION_INFO_ERR;
					dbuf->length = BASIC_SIZE;
				}
				else{
					mapicommd_logging(log_to_file, log_to_syslog, log_fd_info, dbuf, 0);
					dbuf->cmd = GET_FUNCTION_INFO_ACK;
					memcpy(dbuf->data,&funct_info,sizeof(mapi_function_info_t));
					dbuf->length = BASIC_SIZE+sizeof(mapi_function_info_t);
				}
				break;
#ifdef WITH_ADMISSION_CONTROL
			case SET_AUTHDATA:
				fprintf(stdout,"SET_AUTHDATA\n");
				if(!agent_send_authdata(dbuf)){
					dbuf->cmd = SET_AUTHDATA_ACK;
				}
				else{
					dbuf->cmd = ERROR_ACK;
				}

				dbuf->length = BASIC_SIZE;
				break;
#endif
#ifdef WITH_AUTHENTICATION
			case AUTHENTICATE:
				fprintf(stdout, "AUTHENTICATE\n");
				if(!agent_authenticate(dbuf)){
					mapicommd_logging(log_to_file, log_to_syslog, log_fd_info, dbuf, 0);
					dbuf->cmd = AUTHENTICATE_ACK;
				}
				else{
					mapicommd_logging(log_to_file, log_to_syslog, log_fd_info, dbuf, -1);
					dbuf->cmd = ERROR_ACK;
				}
				dbuf->length = BASIC_SIZE;
				break;
#endif
			case MAPI_STATS:
				dev=strdup(dbuf->data);
				mapid_result = mapi_stats(dev, &stats);
				mapicommd_logging(log_to_file, log_to_syslog, log_fd_info, dbuf, mapid_result);
				if(mapid_result <0) {
					dbuf->cmd = MAPI_STATS_ERR;
					mapi_read_error(&errno, errorstr);
					memcpy(dbuf->data, &errno, sizeof(int));
					dbuf->length = BASIC_SIZE+sizeof(int);
				}
				else {
					dbuf->cmd = MAPI_STATS_ACK;
					memcpy(dbuf->data, &stats, sizeof(struct mapi_stat));
					dbuf->length = BASIC_SIZE+sizeof(struct mapi_stat);
				}
				free(dev);
				break;
			default:
				die("Default case found in handle_request loop!\n");
				break;
	        }

		//no need to send responce on mapi_close_flow
		if (dbuf->cmd!=CLOSE_FLOW) {
#ifdef DIMAPISSL
			SSL_write(con,dbuf,dbuf->length);
#else
			send(sock,dbuf, dbuf->length,0);
#endif
		}
	}

	for(i=0;i<ac_fl_size;++i){//close all remaining flows before this thread exits
		if(active_flows[i]>0){//this should always be positive or realloc does not work
			mapi_close_flow(active_flows[i]);
		}
	}
	free(active_flows);
	free(dbuf);
	dbuf = NULL;

	shutdown(sock, SHUT_RDWR);
	close(sock);

#ifdef DIMAPISSL
	if (SSL_shutdown(con) == -1)	// shut down a TLS/SSL connection
		ERR_print_errors_fp(stderr);

	SSL_free(con);			// decrements the reference count of ssl, and removes the SSL structure pointed to by ssl
       					// frees up the allocated memory if the the reference count has reached 0
#endif

	/* update the global service counter */
	service_count++;
	DEBUG_CMD(Debug_Message("<+> thread %lu exiting", pthread_self()));
	DEBUG_CMD(Debug_Message("<+> total sockets served: %d", service_count));

	if(log_to_file){
		file_size = acquire_write_lock(log_fd_info);
		write_to_file(log_fd_info, "MAPICOMMD: thread %lu exiting at ", pthread_self());
		write_date(log_fd_info);
		write_to_file(log_fd_info, "\nMAPICOMMD: Total sockets served: %d\n", service_count);
		release_write_lock(log_fd_info, file_size);
	}
	
	pthread_exit((void *)0);
}

int die(char *msg){

	long file_size;
	
	if(log_to_file){
		file_size = acquire_write_lock(log_fd_info);
		write_to_file(log_fd_info, "MAPICOMMD: %s\n", msg);
		release_write_lock(log_fd_info, file_size);
	}

	perror(msg);
	return EXIT_FAILURE;
}

//calls the appropriate mapi_apply_function and returns the fid from mapid
int getfid(struct dmapiipcbuf *dbuf){
	int result;

	char *function = (char *)dbuf->data;
	char *data = (char *)(dbuf->data+strlen(function)+1);

	result = mapi_apply_function(dbuf->fd, function, data);
	return (result);
}

void mapicommd_shutdown(int exit_value){

#ifdef DIMAPISSL
	
	if(ctx != NULL)
		SSL_CTX_free(ctx);	// decrements the reference count of ctx, and removes the SSL_CTX object pointed to by ctx
					// frees up the allocated memory if the the reference count has reached 0
	CRYPTO_cleanup_all_ex_data();	// clean up all allocated state
	ERR_free_strings();		// frees all previously loaded error strings
	ERR_remove_state(0);		// the current thread will have its error queue removed
	EVP_cleanup();			// removes all ciphers and digests from the table
#endif
	
	if(log_to_file){
		
		daemon_terminated(log_fd_info, "MAPICOMMD", daemonize, 0);
		daemon_terminated(log_fd_debug, "MAPICOMMD", daemonize, 0);

	}
	if(log_to_syslog)
		log_message("MAPICOMMD was terminated %s", daemonize ? " ( was running as daemon )" : "");

	exit(exit_value);
}
