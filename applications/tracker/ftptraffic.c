#include "util.h"

count_results *head = NULL;

// shared objects

int *port_flag;
pthread_mutex_t *port_mutex;


char *extract_ports(struct mapipkt *pkt)
{
	unsigned char *connection_pkt;
	int size = 0;
	
	connection_pkt = get_tcp_payload(pkt, &size);

	if(size > 3)
	{
		if(strncmp(connection_pkt, "150", 3) == 0)
		{
				char *info, *token;

				info = segment_as_string(connection_pkt, size, '(', ')');

				token = (char *)strtok(info, ",");

				token = (char *)strtok(NULL, "");

				return token;
		}
		else if(strncmp(connection_pkt, "227", 3) == 0)
		{
			char *info, *token;
			short cnt;
			unsigned char newport[2];
			char port[20];
			
			info = segment_as_string(connection_pkt, size, '(', ')');
			
			token = (char *)strtok(info,",");
			
			cnt=1;
			
			while((token = (char *)strtok(NULL,",")))
			{
				cnt++;
			
				if(cnt==5) 
					newport[1]=(unsigned char)atoi(token);
				if(cnt==6) 
					newport[0]=(unsigned char)atoi(token);
			}
			
			sprintf(port, "%u", *((unsigned short *)(&newport[0])));

			return (char *)strdup(port);
		}
	}
	
	return NULL;			
}

void track_ftp_port(int my_pipefd[2])
{
	struct mapipkt *pkt;
	int fd, bufid;

	//	unsigned short port;
	char *port;
	
	/* Create a flow to monitor the control port of FTP: port 21 */

	if(offline)
	{
		fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		fd = mapi_create_flow(DEVICE);
	}

	if(fd < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("Error: %d - %s\n", err_no, err_buffer);
	}	

	mapi_apply_function(fd, "BPF_FILTER", "port 21");

	bufid = mapi_apply_function(fd, "TO_BUFFER");
	
	mapi_connect(fd);

	while(1)
	{
		pkt  = (struct mapipkt*)mapi_get_next_pkt(fd, bufid);

		if(pkt != NULL)
		{
			port = (char *)extract_ports(pkt); 	
	
			if(port != NULL)
			{
				if(write(my_pipefd[1], port, 20) == -1)
				{
					exit(-1);
				}
			
				pthread_mutex_lock(port_mutex);

				*port_flag += 1;

				pthread_mutex_unlock(port_mutex);
			}
		}
	}
}

void track_ftp(int pipef[2])
{
	int fd;

	//	unsigned short port;
	char port[20];
	char filter[64];
	char buf[100];	
	count_results *temp = NULL;

	int f1 , f2;

	// port 21 function ids
	int port21pktc, port21bytesc;

	// generic pkt and byte counters
	int pkts = 0, bytes = 0;
	int passivepkts = 0, passivebytes = 0;
	int all = 0, allbytes = 0;
	int port21pkts = 0, port21bytes = 0;

	int ftp_file;
	int *tm;
	pid_t pid;
	int port_pipefd[2];
	
	mapi_results_t *res = NULL;

	// fork for track_ftp_ports

	ftp_file = open("ftp.bin", O_RDWR | O_CREAT);
	write(ftp_file, &tm, (sizeof(int) + sizeof(pthread_mutex_t)));
	
	port_flag = (int *)mmap(NULL, sizeof(int), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANON, ftp_file, 0);
	port_mutex = (pthread_mutex_t *)mmap(NULL, sizeof(pthread_mutex_t), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANON, ftp_file, 0);

	*port_flag = 0;

	pthread_mutex_init(port_mutex, NULL);

	if(pipe(port_pipefd) == -1)
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
		track_ftp_port(port_pipefd);
	}

	close(port_pipefd[1]);

	
	/* Create a flow to monitor the control port of FTP: port 21 */

	if(offline)
	{
		fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		fd = mapi_create_flow(DEVICE);
	}

	if(fd < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("Error: %d - %s\n", err_no, err_buffer);
	}	

	f1 = mapi_apply_function(fd, "PKT_COUNTER");
	
	if(f1 < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("Error: %d - %s\n", err_no, err_buffer);
	}	

	
	f2 = mapi_apply_function(fd, "BYTE_COUNTER");
	
	if(f2 < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("Error: %d - %s\n", err_no, err_buffer);
	}	

	mapi_apply_function(fd, "BPF_FILTER", "port 21");

	/* Counting FTP packets in port 21 */
	
	port21pktc = mapi_apply_function(fd, "PKT_COUNTER");

	port21bytesc = mapi_apply_function(fd, "BYTE_COUNTER");

	mapi_connect(fd);
	

	while(1)
	{
		int flag = 0;
		
		passivepkts = 0;
		passivebytes = 0;
			
		pthread_mutex_lock(port_mutex);
		
			flag = *port_flag;

			if(flag > 0)
				*port_flag -= 1;

		pthread_mutex_unlock(port_mutex);
				
		if(flag >= 1)
		{
			if(read(port_pipefd[0], (void *)port, 20) == -1)
			{
				printf("error::%s\n", strerror(errno));
			}
			else
			{
				temp = (count_results *)count_results_init();
			
				sprintf(filter, "port %s", port);
			
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
					printf("track_ftp:Error: %d - %s\n", err_no, err_buffer);
				}
	
				if(mapi_apply_function(temp->fd, "BPF_FILTER", filter) < 0)
				{
					char err_buffer[1024];
					int err_no;
					mapi_read_error(&err_no,err_buffer);
					printf("track_ftp:Error: %d - %s\n", err_no, err_buffer);
				}


				temp->pkt_counter = mapi_apply_function(temp->fd, "PKT_COUNTER");

				temp->byte_counter = mapi_apply_function(temp->fd, "BYTE_COUNTER");

//				temp->filter = mapi_apply_function(temp->fd, "BPF_FILTER", "tcp[tcpflags] & (tcp-fin) != 0");//and tcp[tcpflags] & (tcp-ack) != 0");

				temp->filterc = mapi_apply_function(temp->fd, "PKT_COUNTER");

				mapi_connect(temp->fd);

				count_results_append(&head, temp);
			}
			
			flag = 0;
		}

		res	= mapi_read_results(fd, f1);

		if(res)
		{
			all = *((int*)res->res);

			res = NULL;
		}
		
		res = mapi_read_results(fd, f2);
		
		if(res)
		{
			allbytes = *((int*)res->res);

			res = NULL;
		}

		res	= mapi_read_results(fd, port21pktc);

		if(res)
		{
			port21pkts = *((int*)res->res);

			res = NULL;
		}

		res = mapi_read_results(fd, port21bytesc);

		if(res)
		{
			port21bytes = *((int*)res->res);

			res = NULL;
		}


		if(head != NULL)
		{
			for(temp = head; temp != NULL; temp = temp->next)
			{

				int closeflag;
				
				if(temp->open)
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

					passivepkts += temp->pkts;
					passivebytes += temp->bytes;

					closeflag = *((int*)mapi_read_results(temp->fd, temp->filterc)->res);
						
					if(closeflag > 0)
					{
//						printf("closing flow : %d\n", temp->fd);
						
//						mapi_close_flow(temp->fd);

//						temp->open = 0;
					}
				
				}
				else
				{
					passivepkts += temp->pkts;
					passivebytes += temp->bytes;

				}
			}
		}
	
		pkts = port21pkts + passivepkts;
		bytes = port21bytes + passivebytes;

		ftp.pkts = pkts;
		kazaa.bytes = bytes;

		sprintf(buf, "%d %d", pkts, bytes);

		if(write(pipef[1], buf, 100) == 1)
		{
			printf("%s \n", strerror(errno));
		}
		
		pthread_mutex_lock(ftp_mutex);

		*ftp_flag += 1;

		pthread_mutex_unlock(ftp_mutex);
	}
}				 

