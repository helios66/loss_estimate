#include "util.h"

static count_results *head = NULL;

//int main(int argc, char *argv[])
void track_nap(void)
{
	int napfd = 0;
	head = NULL;
	mapi_results_t *res = NULL;
	
	// nap traffic functions and counters
	int nappktf = 0, napbytesf = 0;
	int nappktc = 0, napbytesc = 0;

	// init our struct
	nap.pkts = 0;
	nap.bytes = 0;
	pthread_mutex_init(&nap.lock, NULL);	// PTHREAD_MUTEX_INITIALIZER	

	if(offline)
	{
		napfd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		napfd = mapi_create_flow(DEVICE);
	}
	
	if(napfd < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("tracknap:Error: %d - %s\n", err_no, err_buffer);
	}

	if(mapi_apply_function(napfd, "BPF_FILTER", "port 6699") < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("tracknap:Error: %d - %s\n", err_no, err_buffer);
	}	

	nappktf = mapi_apply_function(napfd, "PKT_COUNTER");

	if(nappktf < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("tracknap:Error: %d - %s\n", err_no, err_buffer);
	}	

	napbytesf = mapi_apply_function(napfd, "BYTE_COUNTER");
		
	if(napbytesf < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("tracknap:Error: %d - %s\n", err_no, err_buffer);
	}	

	if(mapi_connect(napfd) < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("tracknap:Error: %d - %s\n", err_no, err_buffer);
	}	

	while(1)
	{
	
			sleep(2);
		
			res = mapi_read_results(napfd, nappktf);

			if(res)
			{
				nappktc = *((int*)res->res);
				res = NULL;
			}

			res = mapi_read_results(napfd, napbytesf);
			
			if(res)
			{
				napbytesc = *((int*)res->res);
				res = NULL;
			}


			// locking the mutex
			pthread_mutex_lock(&nap.lock);
			
			nap.pkts = nappktc;
			nap.bytes = napbytesc;

			// unlocking the mutex
			pthread_mutex_unlock(&nap.lock);
	}
	
}	 
	
