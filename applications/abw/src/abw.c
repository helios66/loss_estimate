/*
 * Copyright (c) 2006, CESNET
 * All rights reserved.
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the company nor the names of its contributors 
 *       may be used to endorse or promote products derived from this 
 *       software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, 
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY 
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL 
 * THE COMPANY OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; 
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id$
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define __USE_XOPEN
#include <sys/time.h>
#include <time.h>
#include <math.h>
#include <syslog.h>

#include "mapi.h"
#include "mapi/sample.h"

#include "abw_common.h"
#include "abw_time.h"
#include "abw_conf.h"
#include "abw_rrd.h"

#define TV_DIFF_THRESHOLD 500000

/* Should be declared in <math.h>, but is not in my system */
double round(double x);

flow_t *flow[MAX_FLOWS];

int debug=0;
extern int daemonize;

extern tracked_protocol_t tracked_protocols[];
extern protocol_t protocols[];

int main(int argc, char *argv[])
{ 
	configuration_t configuration;
	int i, j;
	struct timeval tm;
	struct timezone tz;
	measurement_t *measurement;
	struct timeval next, wait;
	int subject_id, flow_id;
	unsigned long long packets, bytes;
	double mbps;
	char command[MAX_COMMAND+1];
	char hostname_interface[MAX_HOSTNAME_INTERFACE+1];	/* DiMAPI connect string
															   as "hostname:interface,..." */

	struct timeval tv_start, tv_stop;	/* to measure how fast mapi_read_result()
														responds */
	int tv_diff_pkt, tv_diff_byte;		/* time used by mapi_read_results() */
	int tv_diff_threshold;		/* 1 if threshold was reached */
	mapi_results_t *pkt_counter_res;
	mapi_results_t *byte_counter_res;
	unsigned long long pkt_counter;
	unsigned long long byte_counter;
	int scope_size;
	double pkt_sec;	/* seconds from previous packet result */
	double byte_sec;	/* seconds from previous byte result */
   mapi_flow_info_t info;
   mapi_device_info_t dinfo;

	openlog("abw", LOG_PID, LOG_LOCAL0);
	syslog(LOG_DEBUG, "starting abw");

	memset((void *)&configuration, 0, (size_t)(sizeof(configuration)));

	/* Create global configuration */
	if ((configuration.global=malloc(sizeof(global_t)))==NULL) {
		fprintf(stderr, "%s: malloc() failed\n", __func__);
		return -1;
	}
	memset(configuration.global, 0, sizeof(global_t));

	/* Create first subject, scope, parameters and measurement so that they
      can be filled-in by command-line options */

	/* if ((configuration.subject=new_subject())==NULL) {
      fprintf(stderr, "%s: new_subject() failed\n", __func__);
      return -1;
	}
	if ((configuration.scope=new_scope())==NULL) {
      fprintf(stderr, "%s: new_subject() failed\n", __func__);
      return -1;
	}
	if ((configuration.parameters=new_parameters())==NULL) {
      fprintf(stderr, "%s: new_parameters() failed\n", __func__);
      return -1;
	}

	if ((configuration.measurement=new_measurement())==NULL) {
      fprintf(stderr, "%s: new_measurement() failed\n", __func__);
      return -1;
	} */

	/* Read command line */

	if (read_command_line(argc, argv, &configuration)<0) {
		fprintf(stderr, "%s: read_command_line() failed\n", __func__);
		return -1;
	}

	/* Read configuration file */

	if (configuration.global->conf_filename) {
		if (read_conf_file(&configuration)<0) {
			fprintf(stderr, "%s: read_conf_file() failed\n", __func__);
			return -1;
		}
	}

	/* Fill-in local hostname */

	if (get_local_hostname(&(configuration.global->hostname))<0) {
		fprintf(stderr, "%s: get_local_hostname() failed\n", __func__);
		return -1;
	}

	/* Check if specified values are within acceptable limits */

	if (check_conf(&configuration)<0) {
      fprintf(stderr, "%s: check_conf() failed\n", __func__);
      exit(-1);
	}

	/* Print configuration */

	if (debug)
		print_conf(&configuration);

	if (daemonize) {
		printf("Switching to daemon\n");
		if (continue_as_daemon()<0) {
			fprintf(stderr, "%s: continue_as_daemon() failed\n", __func__);
			return -1;
		}
		printf("Continuing as daemon\n");
	}

	/* 
	 * Create RRD files 
	 */

	/* Go over all measurements */

	measurement=configuration.measurement;
   while (measurement) {

		int parameters_id;
		char *filename;

		parameters_id = measurement->parameters_id;

		/* Go over all protocols */

		j=0;
		while (protocols[j].protocol) {
			if ((filename=
				abw_rrd_create_filename(measurement->scope, 
					parameters_id, protocols[j].protocol))==NULL) {
				fprintf(stderr, "%s: rrd_create_filename() failed\n", 
					__func__);
				return -1;
			}

			if (abw_rrd_create_file(filename)<0) {
				fprintf(stderr, "%s: abw_rrd_create_file() failed\n", __func__);
				return -1;
			}

			j++;
		} /* Go over all protocols */

		/* Go over all tracked protocols */

		j=0;
		while (tracked_protocols[j].protocol) {
			if ((filename=
				abw_rrd_create_filename(measurement->scope, 
					parameters_id, tracked_protocols[j].protocol))==NULL) {
				fprintf(stderr, "%s: rrd_create_filename() failed\n", 
					__func__);
				return -1;
			}

			if (abw_rrd_create_file(filename)<0) {
				fprintf(stderr, "%s: abw_rrd_create_file() failed\n", __func__);
				return -1;
			}

			j++;
		} /* Go over all tracked protocols */

		/* Create RRD file for "all" protocol (all traffic together) */

		if ((filename=
			abw_rrd_create_filename(measurement->scope, 
				parameters_id, "all"))==NULL) {
				fprintf(stderr, "%s: rrd_create_filename() failed\n", 
					__func__);
				return -1;
		}

		if (abw_rrd_create_file(filename)<0) {
			fprintf(stderr, "%s: abw_rrd_create_file() failed\n", __func__);
			return -1;
		}

		measurement=measurement->next;

   } /* while (measurement) */

	/* 
	 * Create MAPI flows 
	 */

	flow_id=0;

	/* Go over all measurements */

	measurement=configuration.measurement;
   while (measurement) {

		/* Go over all monitored protocols */

		i=0;
		while (measurement->protocols_array[i] && i<MAX_PROTOCOLS) {

			int parameters_id;
			char *protocol;

			/* Create data structure to maintain MAPI information */

			if (flow_id>=MAX_FLOWS) {
				fprintf(stderr, "%s: more than %d flows requested\n", __func__,
					MAX_FLOWS);
				return -1;
			}

			if ((flow[flow_id]=new_flow())==NULL) {
  				fprintf(stderr, "%s: new_flow() failed\n", __func__);
  				return -1;
  			}
			flow[flow_id]->measurement=measurement;
			flow[flow_id]->protocol=measurement->protocols_array[i];

			parameters_id = measurement->parameters_id;
			protocol = measurement->protocols_array[i];
				
			if ((flow[flow_id]->rrd_filename=
				abw_rrd_create_filename(measurement->scope, 
					parameters_id, protocol))==NULL) {
				fprintf(stderr, "%s: rrd_create_filename() failed\n", 
					__func__);
				return -1;
			}

			/* 
			 * If scope has only one subject and if hostname is "localhost" or
			 * equal to local hostname, then use MAPI connect string (not DiMAPI)
			 */

			if (!(measurement->scope->subject[1]) && 
				 (!strcmp(measurement->scope->subject[0]->hostname, "localhost") ||
				  !strcmp(measurement->scope->subject[0]->hostname, 
				  		configuration.global->hostname)))

				strcpy(hostname_interface, 
					measurement->scope->subject[0]->interface);

			/* 
			 * Prepare DiMAPI connect string as hostname:interface, ... 
			 */

			else {
				
				j=0; hostname_interface[0]='\0';
      		while (measurement->scope->subject[j] && j<MAX_SUBJECTS) {

					/* Append comma "," */

					if (hostname_interface[0]) {
						if (strlen(hostname_interface)+1>=MAX_HOSTNAME_INTERFACE) {
							fprintf(stderr, "%s: DiMAPI connect string is longer than %d characters\n", __func__, MAX_HOSTNAME_INTERFACE);
							return -1;
						}
						strcat(hostname_interface, ",");
					}

					/* Append next hostname:interface */
					if (strlen(hostname_interface) +
						 strlen(measurement->scope->subject[j]->hostname) +
				 		strlen(measurement->scope->subject[j]->interface) 
							>= MAX_HOSTNAME_INTERFACE) {
         			fprintf(stderr, "%s: DiMAPI connect string is longer than %d characters\n", __func__, MAX_HOSTNAME_INTERFACE);
            		return -1;
         		}
					sprintf(hostname_interface + strlen(hostname_interface), "%s:%s",
						measurement->scope->subject[j]->hostname,
						measurement->scope->subject[j]->interface);
			
					j++;
				} /* while (measurement->scope->subject[j] && j<MAX_SUBJECTS) */

			} /* Creating DiMAPI connect string */

			/* Create a new MAPI flow */

			if (debug)
				printf("%s: mapi_create_flow(%s)\n", __func__, hostname_interface);

  			if ((flow[flow_id]->fd=mapi_create_flow(hostname_interface))<0) {
				fprintf(stderr, "%s: mapi_create_flow(%s) failed\n", __func__,
					hostname_interface);
				fprintf(stderr, "%s: Do you run mapid daemon on the machine where you connect to?\n", __func__);
				fprintf(stderr, "%s: Do you run mapicommd daemon on the machine where you connect to? (if you are connecting to a non-local machine or to multiple machines)\n", __func__);
					return -1;
			}

         /* If this is a MAPI flow (not DiMAPI flow), then set MPLS and VLAN 
				flags according to mapi.conf. Otherwise the flags were set in
				abw.conf */

			if (!strchr(hostname_interface, ':')) {

				if (debug)
					printf("%s: MAPI flow on \"%s\", setting MPLS and VLAN flags from mapi.conf\n", __func__, hostname_interface);

         	if ((mapi_get_flow_info(flow[flow_id]->fd, &info)) < 0){
            	fprintf(stderr, "%s: mapi_get_flow_info() failed\n", __func__);
            	return -1;
         	}

         	if ((mapi_get_device_info(info.devid, &dinfo)) < 0) {
            	fprintf(stderr, "%s: mapi_get_device_info() failed\n", __func__);
            	return -1;
         	}

         	measurement->scope->mpls = dinfo.mpls;
         	measurement->scope->vlan = dinfo.vlan;

			}
			else
				if (debug)
               printf("%s: DiMAPI flow on \"%s\", setting MPLS and VLAN flags from abw.conf\n", __func__, hostname_interface);

			/* Prepare header filter for this protocol */

			if ((flow[flow_id]->tracked_protocol=
				protocol_filter(measurement->parameters->header_filter, 
					flow[flow_id]->protocol, measurement->scope->mpls, 
					measurement->scope->vlan,
					&(flow[flow_id]->header_filter)))<0) {
				fprintf(stderr, "%s: protocol_filter() failed\n", __func__);
				return -1;
			}

			if (debug)
				printf("measurement->parameters->header_filter: %s, flow[flow_id]->protocol: %s, flow[flow_id]->header_filter: %s, track_function: %s\n", (measurement->parameters->header_filter)?measurement->parameters->header_filter:"NULL", flow[flow_id]->protocol, (flow[flow_id]->header_filter)?flow[flow_id]->header_filter:"NULL", (flow[flow_id]->tracked_protocol)?tracked_protocols[flow[flow_id]->tracked_protocol-1].track_function:"none");

			/* Filter based on input port, we can use port number in the first 
				subject of the scope, because all subjects in a scope must have
				the same port number */

			if (measurement->scope->subject[0]->port >= 0) {
				if ((flow[flow_id]->interface_fid=mapi_apply_function(flow[flow_id]->fd, "INTERFACE", measurement->scope->subject[0]->port))<0) {
					fprintf(stderr, "%s: INTERFACE failed\n", __func__);
               return -1;
            }
			}

			/* Note that BPF_FILTER uses compiled header filter that
				selects packets of the given protocol */

			/* BPF_FILTER is applied if a) header_filter was specified in
				[parameters] section or b) protocol other than "all" and other than
				some that requires tracking was specified in [parameters] section or
				c) MPLS is used on links in this [scope] */

			if (flow[flow_id]->header_filter) {
				if (debug)
					printf("%s: mapi_apply_function(%d, BPF_FILTER, \"%s\")\n",
						__func__, flow[flow_id]->fd, flow[flow_id]->header_filter);
				if ((flow[flow_id]->bpf_filter_fid=
					mapi_apply_function(flow[flow_id]->fd, "BPF_FILTER", 
						flow[flow_id]->header_filter))<0) {
						fprintf(stderr, "%s: BPF_FILTER (\"%s\") failed\n", 
							__func__, flow[flow_id]->header_filter);
						return -1;
				}
			}

			/* Track application protocol, BPF_FILTER could have been applied 
				before */

			if (flow[flow_id]->tracked_protocol) {
				if (debug)
					printf("%s: mapi_apply_function(%d, %s)\n", __func__, 
						flow[flow_id]->fd,
						tracked_protocols[flow[flow_id]->tracked_protocol-1].
							track_function);
				if ((flow[flow_id]->track_function_fid=
					mapi_apply_function(flow[flow_id]->fd, 
						tracked_protocols[flow[flow_id]->tracked_protocol-1].
							track_function))<0) {
					fprintf(stderr, "%s: tracking (%s) failed\n", __func__, 
						tracked_protocols[flow[flow_id]->tracked_protocol-1].
							track_function);
					return -1;
				}
			}

			/* Sampling */

			if (measurement->parameters->sau_mode == 'd' && 
				 (unsigned int)(measurement->parameters->sau_threshold) != 1) {
				if ((flow[flow_id]->sample_fid=
					mapi_apply_function(flow[flow_id]->fd, "SAMPLE", 
						measurement->parameters->sau_threshold, PERIODIC))<0) {
					fprintf(stderr, "%s: SAMPLE (PERIODIC, %.02f) failed\n",
						__func__, measurement->parameters->sau_threshold);
					return -1;
				}
			}
			else if (measurement->parameters->sau_mode == 'p' && 
						(unsigned int)(measurement->parameters->sau_threshold) != 1) {
				if ((flow[flow_id]->sample_fid=
        			mapi_apply_function(flow[flow_id]->fd, "SAMPLE", 
						(measurement->parameters->sau_threshold)*100,
						PROBABILISTIC))<0) {
        			fprintf(stderr, "%s: SAMPLE (PROBABILISTIC, %.02f) failed\n", 
						__func__, (measurement->parameters->sau_threshold)*100);
        			return -1;
      		}
			}
	
			/* Payload searching */
	
			if (measurement->parameters->payload_strings[0]) {
				if ((flow[flow_id]->str_search_fid=
        			mapi_apply_function(flow[flow_id]->fd, "STR_SEARCH", 
					measurement->parameters->payload_strings[0], 0, 0))<0) {
           			fprintf(stderr, "%s: STR_SEARCH (%s) failed\n", 
						__func__, measurement->parameters->payload_strings[0]);
        	   		return -1;
       		}
			}

			/* Counting packets and bytes */

			if ((flow[flow_id]->pkt_counter_fid=
        		mapi_apply_function(flow[flow_id]->fd, "PKT_COUNTER"))<0) {
           		fprintf(stderr, "%s: PKT_COUNTER failed\n", __func__);
        		return -1;
  			}

			/* Simultaneous use of PKT_COUNTER and BYTE_COUNTER does not
				work with DAG4.3GE. Temporary hack: always use stflib version */

			if ((flow[flow_id]->byte_counter_fid=
        		mapi_apply_function(flow[flow_id]->fd, "stdflib:BYTE_COUNTER"))<0) {
           		fprintf(stderr, "%s: BYTE_COUNTER failed\n", 
				__func__);
        		return -1;
  			}

			/* Connect to flow */

			if (!configuration.global->no_measure) {
				if (mapi_connect(flow[flow_id]->fd)<0) {
					fprintf(stderr, "%s: mapi_connect() (%s) failed\n", 
						__func__, hostname_interface);
					return -1;
				}

				if ((scope_size=mapi_get_scope_size(flow[flow_id]->fd)) != 
					flow[flow_id]->measurement->scope->subject_no) {
					fprintf(stderr, "%s: mapi_get_scope_size() returned %d for %d subjects\n", __func__, scope_size, flow[flow_id]->measurement->scope->subject_no);
					return -1;
				}
			}

			i++;
			flow_id++;

		} /* while (measurement->protocols_array[i] && i<MAX_PROTOCOLS) */

		measurement=measurement->next;

	} /* while (measurement) */

	if (configuration.global->no_measure || !configuration.measurement)
		return 0;

	/* Periodically get results from MAPI flows */

	while (1) {
		if (gettimeofday(&tm, &tz)<0) {
			fprintf(stderr, "%s: gettimeofday() failed\n", __func__);
			return -1;
		}

		flow_id=0;
		while (flow[flow_id] && flow_id<MAX_FLOWS) {

			int scope_packets, scope_bytes;
	
			if (!configuration.global->no_stdout) {
				printf("%d %u.%u", flow[flow_id]->measurement->scope->id, 
					(unsigned int)(tm.tv_sec), 
					(unsigned int)(tm.tv_usec));
				if (!configuration.global->stdout_simple)
					printf(" %s\n", flow[flow_id]->protocol);
			}

			gettimeofday(&tv_start, NULL);
			if ((pkt_counter_res=mapi_read_results(flow[flow_id]->fd, 
				flow[flow_id]->pkt_counter_fid))==NULL) {
					fprintf(stderr, "%s: mapi_read_results() for flow %d failed\n",
						__func__, flow_id);
			 	return -1;
			}

			gettimeofday(&tv_stop, NULL);
			tv_diff_pkt=timestamp_diff(&tv_start, &tv_stop);

			gettimeofday(&tv_start, NULL);
			if ((byte_counter_res=mapi_read_results(flow[flow_id]->fd, 
				flow[flow_id]->byte_counter_fid))==NULL) {
        			fprintf(stderr, "%s: mapi_read_results() for flow %d failed\n",
             		__func__, flow_id);
          		return -1;
     		}
			gettimeofday(&tv_stop, NULL);
			tv_diff_byte=timestamp_diff(&tv_start, &tv_stop);

			if (tv_diff_pkt>=TV_DIFF_THRESHOLD ||
				 tv_diff_byte>=TV_DIFF_THRESHOLD)
				tv_diff_threshold=1;
			else
				tv_diff_threshold=0;

			if (tv_diff_pkt>=TV_DIFF_THRESHOLD)
				syslog(LOG_DEBUG, "mapi_read_result() for PKT_COUNTER takes %d us for measurement ID %d and protocol %s (threshold %d us reached)", tv_diff_pkt, flow[flow_id]->measurement->id, flow[flow_id]->protocol, TV_DIFF_THRESHOLD);
			if (tv_diff_byte>=TV_DIFF_THRESHOLD)
				syslog(LOG_DEBUG, "mapi_read_result() for BYTE_COUNTER takes %d us for measurement ID %d and protocol %s (threshold %d us reached)", tv_diff_byte, flow[flow_id]->measurement->id, flow[flow_id]->protocol, TV_DIFF_THRESHOLD);

			scope_size = flow[flow_id]->measurement->scope->subject_no;

			scope_packets=0;
			scope_bytes=0;

			for (subject_id=0; subject_id<scope_size; subject_id++) {
	
				pkt_counter=
					*((unsigned long long*)(pkt_counter_res[subject_id].res));
				byte_counter=
					*((unsigned long long*)(byte_counter_res[subject_id].res));

				packets=pkt_counter - flow[flow_id]->pkt_counter[subject_id];
				bytes=byte_counter - flow[flow_id]->byte_counter[subject_id];
				mbps=(double)bytes*8/1000000;

				flow[flow_id]->pkt_counter[subject_id]=pkt_counter;
				flow[flow_id]->byte_counter[subject_id]=byte_counter;

				/* Determine seconds from previous result */

				if (flow[flow_id]->pkt_ts[subject_id])
					pkt_sec=(double)(pkt_counter_res[subject_id].ts -
								flow[flow_id]->pkt_ts[subject_id])/1000000;
				else
					pkt_sec=
						flow[flow_id]->measurement->parameters->interval.tv_sec +
	               (double)(flow[flow_id]->measurement->parameters->interval.tv_usec)/1000000;
		
				if (flow[flow_id]->byte_ts[subject_id])
					byte_sec=(double)(byte_counter_res[subject_id].ts -
						flow[flow_id]->byte_ts[subject_id])/1000000;
				else
					byte_sec=
						flow[flow_id]->measurement->parameters->interval.tv_sec +
	               (double)(flow[flow_id]->measurement->parameters->interval.tv_usec)/1000000;

				scope_packets+=(packets/pkt_sec);
				scope_bytes+=(bytes/byte_sec);

				flow[flow_id]->pkt_ts[subject_id]=
					pkt_counter_res[subject_id].ts;
				flow[flow_id]->byte_ts[subject_id]=
					byte_counter_res[subject_id].ts;

				if (tv_diff_threshold) {
					syslog(LOG_DEBUG, "%s:%s: %.02f seconds from previous result",
						flow[flow_id]->measurement->scope->subject[subject_id]->hostname,
						flow[flow_id]->measurement->scope->subject[subject_id]->interface,
						byte_sec);
				}

				/* Print result */

				if (!configuration.global->no_stdout) {
					if (configuration.global->stdout_simple)
						printf(" %0.2f %0.2f %0.2f", packets/pkt_sec, 
							bytes/byte_sec, mbps/byte_sec);
					else
							printf(" %0.2f packets/s, %0.2f bytes/s, %0.2f Mb/s, time %uus/%uus, interval %0.2fs/%0.2fs\n", 
								packets/pkt_sec, bytes/byte_sec, mbps/byte_sec, 
								tv_diff_pkt, tv_diff_byte, pkt_sec, byte_sec);
				}

			} /* for (subject_id=0; subject_id++; subject_id<scope_size) */

			if (!configuration.global->no_stdout)
				printf("\n");

			/* If interval is at least 1 second, then store results 
			   to RRD file */
				
			if (flow[flow_id]->measurement->parameters->interval.tv_sec) {
				sprintf(command, "rrdtool update %s %u:%lu:%lu:%.6f", 
					 flow[flow_id]->rrd_filename, 
					 (unsigned int)(tm.tv_sec), 
					 (unsigned long)(scope_packets), 
					 (unsigned long)(scope_bytes), 
					 (double)scope_bytes*8/1000000);

				if (configuration.global->debug > 1)
					syslog(LOG_DEBUG, "system(%s)", command);

				if (tm.tv_sec == flow[flow_id]->rrd_ts)
					syslog(LOG_ERR, "duplicate RRD timestamp %u for scope %d\n", (unsigned int)(tm.tv_sec), flow[flow_id]->measurement->scope->id);
				else
					flow[flow_id]->rrd_ts=tm.tv_sec;

				if (debug)
					printf("%s: system(%s)\n", __func__, command);

				if (system(command)<0) {
					fprintf(stderr, "%s: command(%s) failed\n", __func__,
						command);
					return -1;
				}
			}

			flow_id++;

		} /* while (flow[flow_id] && flow_id<MAX_FLOWS) */

		abw_next_timestamp(&(configuration.measurement->parameters->interval), 
			&next, &wait);

		if (!configuration.global->no_stdout && 
			 !configuration.global->stdout_simple) {
     		printf("next.tv_sec: %d, next.tv_usec: %d, wait.tv_sec: %d, wait.tv_usec: %d\n", (int)(next.tv_sec), (int)(next.tv_usec), (int)(wait.tv_sec), (int)(wait.tv_usec));
			printf("===============================================================================\n");
		}

     	usleep(wait.tv_sec * 1000000 + wait.tv_usec);
		 
	} /* while (1) */

	return 0;
} /* main() */
