#include "util.h"

static count_results *head = NULL;

int *filter_flag;
pthread_mutex_t *filter_mutex;

// central flow No
//static int kazfd;
// TO_BUFFER functioon
static int bufferid;

void get_filter(int pipe[2])
{
//	char *filter = NULL;
	struct mapipkt *pkt = NULL;

	close(pipe[0]);
	
	int kazfd;

	unsigned char *connection_pkt;
	int size = 0;
	unsigned char *p;
	char *token;
	int cnt;	
	char filter[100];


	if(offline)
	{
		kazfd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		kazfd = mapi_create_flow(DEVICE);
	}
	
	if(kazfd < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("track_kazaa:Error1: %d - %s\n", err_no, err_buffer);
	}	

	if(mapi_apply_function(kazfd, "STR_SEARCH", "KazaaClient", 0, 1500) < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("track_kazaa:Error2: %d - %s\n", err_no, err_buffer);
	}	

	bufferid = mapi_apply_function(kazfd, "TO_BUFFER");
	
	if(bufferid < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("track_kazaa:Error3: %d - %s\n", err_no, err_buffer);
	}	

	if(mapi_connect(kazfd) < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("track_kazaa:Error4: %d - %s\n", err_no, err_buffer);
	}	


	while(1)
	{
		pkt = (struct mapipkt *)mapi_get_next_pkt(kazfd, bufferid);

		connection_pkt = get_tcp_payload(pkt, &size);

		if(size > 10)
		{
			if(strncmp(connection_pkt, "GIVE ", 5) == 0) 
			{
				if((p = strstr(connection_pkt, "X-Kazaa-IP: ")) != NULL)
				{
					token = (char *)strtok(p, " ");
					
					sprintf(filter, "%s", "host ");

					for(cnt = 0; cnt < 3; cnt++)
					{
						token = (char *)strtok(NULL, ".");

						sprintf(filter, "%s%s.", filter, token);
					}

					token = (char *)strtok(NULL, ":");

					sprintf(filter, "%s%s", filter, token);

					token = (char *)strtok(NULL, "\n");

					sprintf(filter, "port %s", token);
	
					filter[strlen(filter) -1 ] = '\0';

					if(write(pipe[1], filter, 200) == -1)//strlen(filter) + 1) == -1)
					{
						printf("%s\n", strerror(errno));
						exit(-1);
					}

					pthread_mutex_lock(filter_mutex);

					*filter_flag = *filter_flag + 1;
			
					pthread_mutex_unlock(filter_mutex);

				}
				
				if((p = strstr(connection_pkt, "Host: ")) != NULL)
				{
					token = (char *)strtok(p, " ");
				
					sprintf(filter, "%s", "host ");

					for(cnt = 0; cnt < 3; cnt++)
					{
						token = (char *)strtok(NULL, ".");
						sprintf(filter, "%s%s.", filter, token);
					}

					token = (char *)strtok(NULL, ":");
					sprintf(filter, "%s%s", filter, token);
	
					token = (char *)strtok(NULL, "\n");

					sprintf(filter, "port %s", token);
	
					filter[strlen(filter) -1 ] = '\0';

					if(write(pipe[1], filter, 200) == -1)//strlen(filter) + 1) == -1)
					{
						printf("%s\n", strerror(errno));
						exit(-1);
					}

					pthread_mutex_lock(filter_mutex);

					*filter_flag = *filter_flag + 1;
			
					pthread_mutex_unlock(filter_mutex);

				}

				if((p = strstr(connection_pkt, "X-Kazaa-SupernodeIP: ")) != NULL)
				{
					token = (char *)strtok(p, " ");
					
					sprintf(filter, "%s", "host ");

					for(cnt = 0; cnt < 3; cnt++)
					{
						token = (char *)strtok(NULL, ".");

						sprintf(filter, "%s%s.", filter, token);
					}

					token = (char *)strtok(NULL, ":");

					sprintf(filter, "%s%s", filter, token);

					token = (char *)strtok(NULL, "\n");

					sprintf(filter, "port %s", token);
	
					filter[strlen(filter) -1 ] = '\0';

					if(write(pipe[1], filter, 200) == -1)//strlen(filter) + 1) == -1)
					{
						printf("%s\n", strerror(errno));
						exit(-1);
					}

					pthread_mutex_lock(filter_mutex);

					*filter_flag = *filter_flag + 1;
			
					pthread_mutex_unlock(filter_mutex);

				}
			}
		
			if(strncmp(connection_pkt, "GET /", 5) == 0) 
			{
				if((p = strstr(connection_pkt, "X-Kazaa-IP: ")) != NULL)
				{
					token = (char *)strtok(p, " ");
				
					sprintf(filter, "%s", "host ");

					for(cnt = 0; cnt < 3; cnt++)
					{
						token = (char *)strtok(NULL, ".");

						sprintf(filter, "%s%s.", filter, token);
					}

					token = (char *)strtok(NULL, ":");

					sprintf(filter, "%s%s", filter, token);

					token = (char *)strtok(NULL, "\n");

					sprintf(filter, "port %s", token);
	
					filter[strlen(filter) -1 ] = '\0';

					if(write(pipe[1], filter, 200) == -1)//strlen(filter) + 1) == -1)
					{
						printf("%s\n", strerror(errno));
						exit(-1);
					}

					pthread_mutex_lock(filter_mutex);

					*filter_flag = *filter_flag + 1;
			
					pthread_mutex_unlock(filter_mutex);

				}

				
				if((p = strstr(connection_pkt, "Host: ")) != NULL)
				{
					token = (char *)strtok(p, " ");
				
					sprintf(filter, "%s", "host ");

					for(cnt = 0; cnt < 3; cnt++)
					{
						token = (char *)strtok(NULL, ".");
						sprintf(filter, "%s%s.", filter, token);
					}

					token = (char *)strtok(NULL, ":");
					sprintf(filter, "%s%s", filter, token);

					token = (char *)strtok(NULL, "\n");

					sprintf(filter, "port %s", token);
	
					filter[strlen(filter) -1 ] = '\0';
			
					if(write(pipe[1], filter, 200) == -1)//strlen(filter) + 1) == -1)
					{
						printf("%s\n", strerror(errno));
						exit(-1);
					}

					pthread_mutex_lock(filter_mutex);

					*filter_flag = *filter_flag + 1;
			
					pthread_mutex_unlock(filter_mutex);

				}

				if((p = strstr(connection_pkt, "X-Kazaa-SupernodeIP: ")) != NULL)
				{
					token = (char *)strtok(p, " ");
					
					sprintf(filter, "%s", "host ");

					for(cnt = 0; cnt < 3; cnt++)
					{
						token = (char *)strtok(NULL, ".");

						sprintf(filter, "%s%s.", filter, token);
					}

					token = (char *)strtok(NULL, ":");

					sprintf(filter, "%s%s", filter, token);

					token = (char *)strtok(NULL, "\n");

					sprintf(filter, "port %s", token);
	
					filter[strlen(filter) -1 ] = '\0';

					if(write(pipe[1], filter, 200) == -1)//strlen(filter) + 1) == -1)
					{
						printf("%s\n", strerror(errno));
						exit(-1);
					}

					pthread_mutex_lock(filter_mutex);

					*filter_flag = *filter_flag + 1;
			
					pthread_mutex_unlock(filter_mutex);

				}
			}

		
			if(strncmp(connection_pkt, "HTTP/1.1 2", 10) == 0)
			{
				if((p = strstr(connection_pkt, "X-Kazaa-IP: ")) != NULL)
				{
					token = (char *)strtok(p, " ");
				
					sprintf(filter, "%s", "host ");

					for(cnt = 0; cnt < 3; cnt++)
					{
						token = (char *)strtok(NULL, ".");
						sprintf(filter, "%s%s.", filter, token);
					}

					token = (char *)strtok(NULL, ":");
					sprintf(filter, "%s%s", filter, token);

					token = (char *)strtok(NULL, "\n");

					sprintf(filter, "port %s", token);
	
					filter[strlen(filter) -1 ] = '\0';

					if(write(pipe[1], filter, 200) == -1)//strlen(filter) + 1) == -1)
					{
						printf("%s\n", strerror(errno));
						exit(-1);
					}

					pthread_mutex_lock(filter_mutex);

					*filter_flag = *filter_flag + 1;
			
					pthread_mutex_unlock(filter_mutex);

				}
			
				if((p = strstr(connection_pkt, "Host: ")) != NULL)
				{
					token = (char *)strtok(p, " ");
				
					sprintf(filter, "%s", "host ");

					for(cnt = 0; cnt < 3; cnt++)
					{
						token = (char *)strtok(NULL, ".");
						sprintf(filter, "%s%s.", filter, token);
					}

					token = (char *)strtok(NULL, ":");
					sprintf(filter, "%s%s", filter, token);

					token = (char *)strtok(NULL, "\n");

					sprintf(filter, "port %s", token);
	
					filter[strlen(filter) -1 ] = '\0';

					if(write(pipe[1], filter, 200) == -1)//strlen(filter) + 1) == -1)
					{
						printf("%s\n", strerror(errno));
						exit(-1);
					}

					pthread_mutex_lock(filter_mutex);

					*filter_flag = *filter_flag + 1;
			
					pthread_mutex_unlock(filter_mutex);

				}
			
				if((p = strstr(connection_pkt, "X-Kazaa-SupernodeIP: ")) != NULL)
				{
					token = (char *)strtok(p, " ");
					
					sprintf(filter, "%s", "host ");

					for(cnt = 0; cnt < 3; cnt++)
					{
						token = (char *)strtok(NULL, ".");

						sprintf(filter, "%s%s.", filter, token);
					}

					token = (char *)strtok(NULL, ":");

					sprintf(filter, "%s%s", filter, token);

					token = (char *)strtok(NULL, "\n");

					sprintf(filter, "port %s", token);
	
					filter[strlen(filter) -1 ] = '\0';

					if(write(pipe[1], filter, 200) == -1)//strlen(filter) + 1) == -1)
					{
						printf("%s\n", strerror(errno));
						exit(-1);
					}

					pthread_mutex_lock(filter_mutex);

					*filter_flag = *filter_flag + 1;
			
					pthread_mutex_unlock(filter_mutex);

				}
			}
		}
	}// while (1)
}

void track_kazza(int fd[2])
{
	head = NULL;
	mapi_results_t *res = NULL;
	char buf[1000];
	
	count_results *temp = NULL;
	char filter[40];

	// kazza traffic functions and counters
	int kazzapktf = 0, kazzabytesf = 0;
	int kazzapktc = 0, kazzabytesc = 0;
	int kazfd;

	int filter_pipefd[2];
	int flag;
	int kaz_file;
	int tm;
	pid_t pid;

	// init our struct
	kazaa.pkts = 0;
	kazaa.bytes = 0;

	close(fd[0]);

	kaz_file = open("kazza.bin", O_RDWR | O_CREAT);
	write(kaz_file, &tm, (sizeof(int) + sizeof(pthread_mutex_t)));

	filter_flag = (int *)mmap(NULL, sizeof(int), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANON, kaz_file, 0);
	filter_mutex = (pthread_mutex_t *)mmap(NULL, sizeof(pthread_mutex_t), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANON, kaz_file, 0);

	*filter_flag = 0;
	pthread_mutex_init(filter_mutex, NULL);

	if(pipe(filter_pipefd) == -1)
	{
		perror("pipe");
        exit(1);
	}

	if((pid = fork()) == -1)
	{
		perror("error::fork::process not created\n");
	}
	else if(pid == 0)
	{
		get_filter(filter_pipefd);
	}
	
	close(filter_pipefd[1]);

	if(offline)
	{
		kazfd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		kazfd = mapi_create_flow(DEVICE);
	}
	
	if(kazfd < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("track_kazaa:Error5: %d - %s\n", err_no, err_buffer);
	}	

	if(mapi_apply_function(kazfd, "STR_SEARCH", "KazaaClient", 0, 1500) < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("track_kazaa:Error6: %d - %s\n", err_no, err_buffer);
	}	

	kazzapktf = mapi_apply_function(kazfd, "PKT_COUNTER");
	
	if(kazzapktf < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("track_kazaa:Error7: %d - %s\n", err_no, err_buffer);
	}	

	kazzabytesf = mapi_apply_function(kazfd, "BYTE_COUNTER");
		
	if(kazzabytesf < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("track_kazaa:Error8: %d - %s\n", err_no, err_buffer);
	}	

	if(mapi_connect(kazfd) < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("track_kazaa:Error9: %d - %s\n", err_no, err_buffer);
	}	

	// Adding support for joltid  P2P provider in port 3531

	temp = (count_results *)count_results_init();	
	
	temp->filt = (char *)strdup("port 3531");
					
	if(offline)
	{
		temp->fd = mapi_create_offline_flow(readfile, MFF_PCAP); 
	}
	else
	{
		temp->fd = mapi_create_flow(DEVICE);
	}
	
	if(temp->fd < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("track_kazaa:Error10: %d - %s\n", err_no, err_buffer);
	}
	
	if(mapi_apply_function(temp->fd, "BPF_FILTER", temp->filt) < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("track_kazaa:Error11: %d - %s\n", err_no, err_buffer);
	}

	temp->pkt_counter = mapi_apply_function(temp->fd, "PKT_COUNTER");
	
	temp->byte_counter = mapi_apply_function(temp->fd, "BYTE_COUNTER");
	
	//	temp->filter = mapi_apply_function(temp->fd, "BPF_FILTER", "tcp[tcpflags] & (tcp-fin) != 0 and tcp[tcpflags] & (tcp-ack) != 0");
					  
	temp->filterc = mapi_apply_function(temp->fd, "PKT_COUNTER");

	mapi_connect(temp->fd);

	count_results_append(&head, temp);

	// End of adding joldit
	while(1)
	{
		flag = 0;

		pthread_mutex_lock(filter_mutex);

		flag = *filter_flag;

		if(flag > 0)
		{
			*filter_flag = *filter_flag - 1;
		}

		pthread_mutex_unlock(filter_mutex);

		msync(&kaz_file, (sizeof(int) + sizeof(pthread_mutex_t)), MS_SYNC|MS_INVALIDATE);

		if(flag >= 1)
		{
			if(read(filter_pipefd[0], (void *)filter, 200) == -1)
			{
				printf("error in read filter\n");
			}
			else
			{
				if(head == NULL)
				{
					
		   			temp = (count_results *)count_results_init();	
		
					temp->filt = (char *)strdup(filter);
					
					if(offline)
					{
				   		temp->fd = mapi_create_offline_flow(readfile, MFF_PCAP); 
					}
					else
					{
						temp->fd = mapi_create_flow(DEVICE);
					}

					if(temp->fd < 0)
					{
						char err_buffer[1024];
						int err_no;
						mapi_read_error(&err_no,err_buffer);
						printf("track_kazaa:Error: %d - %s\n", err_no, err_buffer);
					}

				    if(mapi_apply_function(temp->fd, "BPF_FILTER", filter) < 0)
					{
						char err_buffer[1024];
						int err_no;
						mapi_read_error(&err_no,err_buffer);
						printf("track_kazaa:Error: %d - %s\n", err_no, err_buffer);
					}

		   			temp->pkt_counter = mapi_apply_function(temp->fd, "PKT_COUNTER");

		   			temp->byte_counter = mapi_apply_function(temp->fd, "BYTE_COUNTER");

				//	temp->filter = mapi_apply_function(temp->fd, "BPF_FILTER", "tcp[tcpflags] & (tcp-fin) != 0 and tcp[tcpflags] & (tcp-ack) != 0");
					  
					temp->filterc = mapi_apply_function(temp->fd, "PKT_COUNTER");

		   			mapi_connect(temp->fd);

					count_results_append(&head, temp);

				}
				else
				{
					int again = 0;
					count_results *t;

					for(t = head; t != NULL; t = t->next)
					{
						if(strcmp(t->filt, filter) == 0)
						{
							again = 1;

							break;
						}
						if(t->next == NULL)
						{
							break;
						}
					}

					if(again == 0)
					{
						temp = (count_results *)count_results_init();	
		
						temp->filt = (char*)strdup(filter);
							
						if(offline)
						{
							temp->fd = mapi_create_offline_flow(readfile, MFF_PCAP); 
						}
						else
						{
							temp->fd = mapi_create_flow(DEVICE);
						}

						if(temp->fd < 0)
						{
							char err_buffer[1024];
							int err_no;
							mapi_read_error(&err_no,err_buffer);
							printf("track_kazaa:Error: %d - %s\n", err_no, err_buffer);
						}

			    		if(mapi_apply_function(temp->fd, "BPF_FILTER", filter) < 0)
						{
							char err_buffer[1024];
							int err_no;
							mapi_read_error(&err_no,err_buffer);
							printf("track_kazaa:Error: %d - %s\n", err_no, err_buffer);
						}

				   		temp->pkt_counter = mapi_apply_function(temp->fd, "PKT_COUNTER");
	
						temp->byte_counter = mapi_apply_function(temp->fd, "BYTE_COUNTER");

//		   		temp->filter = mapi_apply_function(temp->fd, "BPF_FILTER", "tcp[tcpflags] & (tcp-fin) != 0 and tcp[tcpflags] & (tcp-ack) != 0");
				  
					   	temp->filterc = mapi_apply_function(temp->fd, "PKT_COUNTER");

	   					mapi_connect(temp->fd);

						count_results_append(&head, temp);

					} // if(again)
				}//else of if(head != NULL)
			}

			flag = 0;
		}

	//	sleep(2);

		kazzapktc = 0;
		kazzabytesc = 0;

		count_results *temp = NULL;

		int t;

		kazzapktc = 0;
		kazzabytesc = 0;

		if(head != NULL)
		{
			for(temp = head; temp != NULL; temp = temp->next)
			{
				if(temp->open == 1)
				{
					res = mapi_read_results(temp->fd, temp->pkt_counter);

					if(res)
					{
						temp->pkts = *((int*)res->res);

						res = NULL;
					}
					
					res = mapi_read_results(temp->fd, temp->byte_counter);
				
					if(res)
					{
						temp->bytes = *((int*)res->res);

						res = NULL;
					}

					kazzapktc += temp->pkts;
					kazzabytesc += temp->bytes;
					
					res = mapi_read_results(temp->fd, temp->filterc);

					if(res)
					{
						t = *((int*)res->res);

						res = NULL;
					}
/*
					if(t > 0)
					{
						printf("closing flow : %d\n", temp->fd);
	
						mapi_close_flow(temp->fd);
	
						temp->open = 0;
					}
*/
				}
				else
				{
					kazzapktc += temp->pkts;
					kazzabytesc += temp->bytes;
				}
			}// for
		}// if(head)

		res = mapi_read_results(kazfd, kazzapktf);
			
		if(res)
		{
			kazzapktc += *((int*)res->res);

			res = NULL;
		}
			
		res = mapi_read_results(kazfd, kazzabytesf);
		
		if(res)
		{
			kazzabytesc += *((int*)res->res);

			res = NULL;
		}
		
		kazaa.pkts = kazzapktc;
		kazaa.bytes = kazzabytesc;

		sprintf(buf, "%d %d", kazzapktc, kazzabytesc);

		if(write(fd[1], buf, 200) == -1)
		{
			printf("%s \n", strerror(errno));
		}

		
		pthread_mutex_lock(kaz_mutex);

		*kaz_flag += 1;

		pthread_mutex_unlock(kaz_mutex);

		//sleep(2);
		
	}// while(1)
}	 

