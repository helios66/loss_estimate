#include "util.h"

#define _GNU_SOURCE
#include <stdio.h>

#define FilE "mail"

static count_results *head = NULL;

void track_mail(void)
{
	FILE *fp;
	char *line = NULL;
    size_t len = 0;
    ssize_t read;
	count_results *temp = NULL;

	int mailpkts = 0, mailbytes =0;
	mapi_results_t *res = NULL;
	
	// init our struct
	mail.pkts = 0;
	mail.bytes = 0;
	pthread_mutex_init(&mail.lock, NULL);	// PTHREAD_MUTEX_INITIALIZER
	
	fp = fopen(FilE, "r");
	
	if (fp == NULL)
	{
		exit(EXIT_FAILURE);
	}
     
	while((read = getline(&line, &len, fp)) != -1)
	{
		if(line[0] != '#' && read > 4)
		{
		//	printf("Retrieved line of length %zu :\n", read);
		//	printf("%s", line);

			temp = count_results_init();
			temp->filt = (char *)strdup(line);

			if(offline)
			{
				temp->fd = mapi_create_offline_flow(readfile, MFF_PCAP);
			}
			else
			{
				temp->fd = mapi_create_flow(DEVICE);
			}

			temp->filter = mapi_apply_function(temp->fd, "BPF_FILTER", line);

			temp->pkt_counter = mapi_apply_function(temp->fd, "PKT_COUNTER");

			temp->byte_counter = mapi_apply_function(temp->fd, "BYTE_COUNTER");
		
			mapi_connect(temp->fd);			

			count_results_append(&head, temp);
		}
	}
	
    if (line)
       free(line);
	   
	while(1)
	{
		mailpkts = 0;
		mailbytes = 0;

		sleep(2);
		
		for(temp = head; temp != NULL; temp = temp->next)
		{
			res = mapi_read_results(temp->fd, temp->pkt_counter);
			
			if(res)
			{
				mailpkts += *((int*)res->res);

				res = NULL;
			}
			
			res = mapi_read_results(temp->fd, temp->byte_counter);

			if(res)
			{
				mailbytes += *((int*)res->res);

				res = NULL;
			}
		}

		pthread_mutex_lock(&mail.lock);
		
		mail.pkts = mailpkts;
		mail.bytes = mailbytes;

		pthread_mutex_unlock(&mail.lock);
	}		   
}
