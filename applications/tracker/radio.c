#include "util.h"

typedef struct ips
{
	char *src;
	char *dst;

	struct ips *next;
}IPS;

int *icy_flag;
pthread_mutex_t *icy_mutex;

int *rtsp_flag;
pthread_mutex_t *rtsp_mutex;

int *real_flag;
pthread_mutex_t *real_mutex;

void get_icy(int my_pipefd[2])
{
	int go = 1;
	int fd = 0;
	int tobuffer;
	struct mapipkt *pkt;

	IPS *head = NULL, *temp = NULL;

	unsigned char *payload;
	struct iphdr *iphd;
	struct tcphdr *tcphd;
	
	char src_ip[20];
	char dst_ip[20];
	char src_port[20];
	char dst_port[20];
	
	char filter[200];
	
	close(my_pipefd[0]);

	if(offline)
	{
		fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		fd = mapi_create_flow(DEVICE);
	}

	mapi_apply_function(fd, "STR_SEARCH", "ICY 200 OK");

	tobuffer = mapi_apply_function(fd, "TO_BUFFER");
	
	mapi_connect(fd);

	while(1)
	{
		pkt = mapi_get_next_pkt(fd, tobuffer);
	
		printf("fount icy\n");
		payload = &pkt->pkt + sizeof(struct ether_header);

		iphd = (struct iphdr *)payload;
		
		sprintf(src_ip, "%u", htons(iphd->saddr));
		sprintf(dst_ip, "%u", htons(iphd->daddr));
	
		payload = (unsigned char *)(payload + (iphd->ihl * 4));
		
		tcphd = (struct tcphdr *)payload;

		sprintf(src_port, "%u", tcphd->source);
		sprintf(dst_port, "%u", tcphd->dest);

//		sprintf(filter, "(src host %s and dst host %s) or (src host %s and dst host %s)", src_ip, dst_ip, dst_ip, src_ip);
		sprintf(filter, "src host %s and dst host %s and not port 80 and not port 554", src_ip, dst_ip);

		temp = (IPS *)malloc(sizeof(IPS));

		temp->src = strdup(src_ip);
		temp->dst = strdup(dst_ip);
		
		if(head == NULL)
		{
			go = 1;

			head = temp;
			temp->next = NULL;
		}
		else
		{
			IPS *tmp = NULL;
			
			for(temp = head; tmp != NULL; tmp = tmp->next)
			{
				if(((strcmp(temp->src, tmp->src) == 1) && (strcmp(temp->dst, tmp->dst) == 1)) || ((strcmp(temp->src, tmp->dst) == 1) && (strcmp(temp->dst, tmp->src) == 1)))
				{
					go = 0;
				}
			}

			if(go == 1)
			{
				temp->next = head;
				head = temp;
			}
		}
				
		printf("\nfilter : %s\n", filter);

		if(go == 1)
		{
			if(write(my_pipefd[1], filter, 200) == -1)
			{
				printf("%s\n", strerror(errno));
				exit(-1);
			}
		
			pthread_mutex_lock(icy_mutex);

			*icy_flag += 1;

			pthread_mutex_unlock(icy_mutex);
		}

		go = 1;
	}// while
}

void get_rtsp(int my_pipefd[2])
{
	int fd = 0;
	int tobuffer;
	struct mapipkt *pkt;

	int go = 1;	
	IPS *head = NULL, *temp = NULL;
	
	unsigned char *payload;
	struct iphdr *iphd;
	struct tcphdr *tcphd;
	
	char src_ip[20];
	char dst_ip[20];
	char src_port[20];
	char dst_port[20];
	
	char filter[200];
	
	close(my_pipefd[0]);

	if(offline)
	{
		fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		fd = mapi_create_flow(DEVICE);
	}

	mapi_apply_function(fd, "STR_SEARCH", "rtsp:");//"OPTIONS rtsp://");//"RTSP/1.0 200 OK");

	tobuffer = mapi_apply_function(fd, "TO_BUFFER");
	
	mapi_connect(fd);

	while(1)
	{
		pkt = mapi_get_next_pkt(fd, tobuffer);

		printf("fount rtsp\n");
		
		payload = &pkt->pkt + sizeof(struct ether_header);

		iphd = (struct iphdr *)payload;
		
		sprintf(src_ip, "%u", htons(iphd->saddr));
		sprintf(dst_ip, "%u", htons(iphd->daddr));
	
		payload = (unsigned char *)(payload + (iphd->ihl * 4));
		
		tcphd = (struct tcphdr *)payload;

		sprintf(src_port, "%u", tcphd->source);
		sprintf(dst_port, "%u", tcphd->dest);

//		sprintf(filter, "(src host %s and dst host %s) or (src host %s and dst host %s)", src_ip, dst_ip, dst_ip, src_ip);
		sprintf(filter, "src host %s and dst host %s and not port 80 and not port 554", src_ip, dst_ip);

		printf("\nfilter : %s\n", filter);
	
		temp = (IPS *)malloc(sizeof(IPS));

		temp->src = strdup(src_ip);
		temp->dst = strdup(dst_ip);
		
		if(head == NULL)
		{
			go = 1;

			head = temp;
			temp->next = NULL;
		}
		else
		{
			IPS *tmp = NULL;
			
			for(temp = head; tmp != NULL; tmp = tmp->next)
			{
				if(((strcmp(temp->src, tmp->src) == 1) && (strcmp(temp->dst, tmp->dst) == 1)) || ((strcmp(temp->src, tmp->dst) == 1) && (strcmp(temp->dst, tmp->src) == 1)))
				{
					printf("found same\n");
					go = 0;
				}
			}

			if(go == 1)
			{
				temp->next = head;
				head = temp;
			}
		}

		if(go == 1)
		{
			if(write(my_pipefd[1], filter, 200) == -1)
			{
				printf("%s\n", strerror(errno));
				exit(-1);
			}
		
			pthread_mutex_lock(rtsp_mutex);

			*rtsp_flag += 1;

			pthread_mutex_unlock(rtsp_mutex);
		}

		go = 1;

	}// while
}



void get_real(int my_pipefd[2])
{
	int fd = 0;
	int tobuffer;
	struct mapipkt *pkt;

	int go = 1;
	IPS *head = NULL, *temp = NULL;
	
	unsigned char *payload;
	struct iphdr *iphd;
	struct tcphdr *tcphd;
	
	char src_ip[20];
	char dst_ip[20];
	char src_port[20];
	char dst_port[20];
	
	char filter[200];
	
	close(my_pipefd[0]);
	
	if(offline)
	{
		fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		fd = mapi_create_flow(DEVICE);
	}

	mapi_apply_function(fd, "STR_SEARCH", "audio/x-pn-realaudio");

	tobuffer = mapi_apply_function(fd, "TO_BUFFER");
	
	mapi_connect(fd);

	while(1)
	{
		pkt = mapi_get_next_pkt(fd, tobuffer);

		printf("fount real\n");
		
		payload = &pkt->pkt + sizeof(struct ether_header);

		iphd = (struct iphdr *)payload;
		
		sprintf(src_ip, "%u", htons(iphd->saddr));
		sprintf(dst_ip, "%u", htons(iphd->daddr));
	
		payload = (unsigned char *)(payload + (iphd->ihl * 4));
		
		tcphd = (struct tcphdr *)payload;

		sprintf(src_port, "%u", htons(tcphd->source));
		sprintf(dst_port, "%u", htons(tcphd->dest));

//		sprintf(filter, "(src host %s and dst host %s) or (src host %s and dst host %s)", src_ip, dst_ip, dst_ip, src_ip);
		sprintf(filter, "src host %s and dst host %s and not port 80 and not port 554", src_ip, dst_ip);
		
		printf("\nfilter : %s\n", filter);
	
		temp = (IPS *)malloc(sizeof(IPS));

		temp->src = strdup(src_ip);
		temp->dst = strdup(dst_ip);
		
		if(head == NULL)
		{
			go = 1;

			head = temp;
			temp->next = NULL;
		}
		else
		{
			IPS *tmp = NULL;
			
			for(temp = head; tmp != NULL; tmp = tmp->next)
			{
				if(((strcmp(temp->src, tmp->src) == 1) && (strcmp(temp->dst, tmp->dst) == 1)) || ((strcmp(temp->src, tmp->dst) == 1) && (strcmp(temp->dst, tmp->src) == 1)))
				{
					printf("found same\n");
					go = 0;
				}
			}

			if(go == 1)
			{
				temp->next = head;
				head = temp;
			}
		}



		if(go == 1)
		{
			if(write(my_pipefd[1], filter, 200) == -1)
			{
				printf("%s\n", strerror(errno));
				exit(-1);
			}
		
			pthread_mutex_lock(real_mutex);
	
			*real_flag += 1;

			pthread_mutex_unlock(real_mutex);
		}

		go = 1;

	}// while
}

void track_realaudio(int pipefd[2])
{
	int icy_pipefd[2];
	int rtsp_pipefd[2];
	int real_pipefd[2];
	int pid = 0;
	int flag = 0;
	int icy_file, rtsp_file, real_file;

	char tm[3 * (sizeof(int) + sizeof(pthread_mutex_t))];
	char filter[200];

	mapi_results_t *res = NULL;
	int pkts = 0, bytes = 0;

	count_results *head = NULL, *temp = NULL;

	close(pipefd[0]);

	icy_file = open("audio.bin", O_RDWR | O_CREAT);
	write(icy_file, &tm, (sizeof(int) + sizeof(pthread_mutex_t)));

	icy_flag = (int *)mmap(NULL, sizeof(int), PROT_READ|PROT_WRITE, MAP_SHARED, icy_file, 0);
	icy_mutex = (pthread_mutex_t *)mmap(NULL, sizeof(pthread_mutex_t), PROT_READ|PROT_WRITE, MAP_SHARED, icy_file, 0);

	rtsp_file = open("rtsp.bin", O_RDWR | O_CREAT);
	write(rtsp_file, &tm, (sizeof(int) + sizeof(pthread_mutex_t)));

	rtsp_flag = (int *)mmap(NULL, sizeof(int), PROT_READ|PROT_WRITE, MAP_SHARED, rtsp_file, 0);
	rtsp_mutex = (pthread_mutex_t *)mmap(NULL, sizeof(pthread_mutex_t), PROT_READ|PROT_WRITE, MAP_SHARED, rtsp_file, 0);

	real_file = open("real.bin", O_RDWR | O_CREAT);
	write(real_file, &tm, (sizeof(int) + sizeof(pthread_mutex_t)));

	real_flag = (int *)mmap(NULL, sizeof(int), PROT_READ|PROT_WRITE, MAP_SHARED, real_file, 0);
	real_mutex = (pthread_mutex_t *)mmap(NULL, sizeof(pthread_mutex_t), PROT_READ|PROT_WRITE, MAP_SHARED, real_file, 0);

	*icy_flag = 0;
	*rtsp_flag = 0;
	*real_flag = 0;
	
	pthread_mutex_init(icy_mutex, NULL);
	pthread_mutex_init(rtsp_mutex, NULL);
	pthread_mutex_init(real_mutex, NULL);
	
	if(pipe(icy_pipefd) == -1)
	{
		perror("pipe(icy_pipefd)\n");
	}

	if(pipe(rtsp_pipefd) == -1)
	{
		perror("pipe(rtsp_pipefd)\n");
	}

	if(pipe(real_pipefd) == -1)
	{
		perror("pipe(real_pipefd)\n");
	}
	
	if((pid = fork()) < 0)
	{
		perror("error at fork\n");
	}
	else if(pid == 0)
	{
		get_icy(icy_pipefd);
	}

	if((pid = fork()) < 0)
	{
		perror("error at fork\n");
	}
	else if(pid == 0)
	{
		get_rtsp(rtsp_pipefd);
	}
	
	if((pid = fork()) < 0)
	{
		perror("error at fork\n");
	}
	else if(pid == 0)
	{
		get_real(real_pipefd);
	}
	
	close(icy_pipefd[1]);
	close(rtsp_pipefd[1]);
	close(real_pipefd[1]);

	// init known port flow

	temp = count_results_init();
					
	temp->filt = strdup("port 554");

	if(offline)
	{
		temp->fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		temp->fd = mapi_create_flow(DEVICE);
	}

	mapi_apply_function(temp->fd, "BPF_FILTER", "port 554 and not port 80");

	temp->pkt_counter = mapi_apply_function(temp->fd, "PKT_COUNTER");

	temp->byte_counter = mapi_apply_function(temp->fd, "BYTE_COUNTER");

	mapi_connect(temp->fd);

	count_results_append(&head, temp);

	while(1)
	{

		sleep(2);

		flag = 0;

		pthread_mutex_lock(icy_mutex);

		flag = *icy_flag;

		if(flag > 0)
		*icy_flag -= 1;

		pthread_mutex_unlock(icy_mutex);

		if(flag >= 1)
		{
			if(read(icy_pipefd[0], (void *)filter, 200) == -1)
			{
				printf("%s\n", strerror(errno));
				exit(-1);
			}
			else
			{
				int go = 1;

				for(temp = head; temp != NULL; temp = temp->next)
				{
					if(strcmp(temp->filt, filter) == 0)
					{
						go = 0;
						break;
					}
				}

				if(go == 1)
				{
	//				printf(" in herre\n");
					temp = count_results_init();
					
					temp->filt = strdup(filter);

					if(offline)
					{
						temp->fd = mapi_create_offline_flow(readfile, MFF_PCAP);
					}
					else
					{
						temp->fd = mapi_create_flow(DEVICE);
					}

//					mapi_apply_function(temp->fd, "BPF_FILTER", "not port 80");

					mapi_apply_function(temp->fd, "BPF_FILTER", filter);

					temp->pkt_counter = mapi_apply_function(temp->fd, "PKT_COUNTER");

					temp->byte_counter = mapi_apply_function(temp->fd, "BYTE_COUNTER");

					mapi_connect(temp->fd);

					count_results_append(&head, temp);
				}
			}

			flag = 0;
		}// if(flag)

		pthread_mutex_lock(rtsp_mutex);

		flag = *rtsp_flag;

		if(flag > 0)
		*rtsp_flag -= 1;

		pthread_mutex_unlock(rtsp_mutex);

		if(flag >= 1)
		{
			if(read(rtsp_pipefd[0], (void *)filter, 200) == -1)
			{
				printf("%s\n", strerror(errno));
				exit(-1);
			}
			else
			{
				int go = 1;
				
				for(temp = head; temp != NULL; temp = temp->next)
				{
					if(strcmp(temp->filt, filter) == 0)
					{
						printf("string same\n");
						go = 0;
						break;
					}
				}

				if(go == 1)
				{
					temp = count_results_init();
					
					temp->filt = strdup(filter);

					if(offline)
					{
						temp->fd = mapi_create_offline_flow(readfile, MFF_PCAP);
					}
					else
					{
						temp->fd = mapi_create_flow(DEVICE);
					}

//mapi_apply_function(temp->fd, "BPF_FILTER", "not port 80");

					mapi_apply_function(temp->fd, "BPF_FILTER", filter);

					temp->pkt_counter = mapi_apply_function(temp->fd, "PKT_COUNTER");

					temp->byte_counter = mapi_apply_function(temp->fd, "BYTE_COUNTER");

					mapi_connect(temp->fd);

					count_results_append(&head, temp);
				}
			}

			flag = 0;
		}// if(flag)

		pthread_mutex_lock(real_mutex);

		flag = *real_flag;

		if(flag > 0)
		*real_flag -= 1;

		pthread_mutex_unlock(real_mutex);

		if(flag >= 1)
		{
			if(read(real_pipefd[0], (void *)filter, 200) == -1)
			{
				printf("%s\n", strerror(errno));
				exit(-1);
			}
			else
			{
				int go = 1;
				
				for(temp = head; temp != NULL; temp = temp->next)
				{
					if(strcmp(temp->filt, filter) == 0)
					{
						go = 0;
						break;
					}
				}

				if(go == 1)
				{
					temp = count_results_init();
					
					temp->filt = strdup(filter);
					
					if(offline)
					{
						temp->fd = mapi_create_offline_flow(readfile, MFF_PCAP);
					}
					else
					{
						temp->fd = mapi_create_flow(DEVICE);
					}

//mapi_apply_function(temp->fd, "BPF_FILTER", "not port 80");

					mapi_apply_function(temp->fd, "BPF_FILTER", filter);

					temp->pkt_counter = mapi_apply_function(temp->fd, "PKT_COUNTER");

					temp->byte_counter = mapi_apply_function(temp->fd, "BYTE_COUNTER");

					mapi_connect(temp->fd);

					count_results_append(&head, temp);
				}
			}

			flag = 0;
		}// if(flag)
		
		pkts = bytes = 0;

		for(temp = head; temp != NULL; temp = temp->next)
		{
			if(temp->open)
			{
				res = mapi_read_results(temp->fd, temp->pkt_counter);

				if(res)
					temp->pkts = *((int*)res->res);

				res = mapi_read_results(temp->fd, temp->byte_counter);

				if(res)
					temp->bytes = *((int*)res->res);
					 
			}// if temp->open
				
			pkts += temp->pkts;
			bytes += temp->bytes;
		}// for
	
		sprintf(filter , "%d %d", pkts, bytes);

		if(write(pipefd[1], filter, 200) == -1)
		{
			printf("%s\n", strerror(errno));
			exit(-1);
		}
		
		pthread_mutex_lock(realaudio_mutex);

		*realaudio_flag += 1;

		pthread_mutex_unlock(realaudio_mutex);

	
		flag = 0;
	}// while(1)

	return;
}
