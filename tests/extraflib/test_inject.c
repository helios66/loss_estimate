/*******************************************
 *
 *	Testing PKT_COUNTER
 *
 *******************************************/


#include <stdio.h>
#include <unistd.h>
#include "mapi.h"

int main(MAPI_UNUSED int argc, char *argv[])
{
	int fd,fd2;
	int fid,fid2;

	mapi_results_t *cnt,*cnt2;

	if(argc!=3)
	{
		printf("\nWrong arguments\n");
		
		return -1;
	}

	fd=mapi_create_flow(argv[1]);
	mapi_apply_function(fd,"INJECT",argv[2]);
	fid=mapi_apply_function(fd,"PKT_COUNTER");
	
	fd2=mapi_create_flow(argv[2]);
	fid2=mapi_apply_function(fd2,"PKT_COUNTER");

	mapi_connect(fd);
	mapi_connect(fd2);

	while(1) {
		sleep(1);
		cnt=mapi_read_results(fd,fid);
		cnt2=mapi_read_results(fd2,fid2);
		printf("Injected to interface %s : %d\n",argv[2],*((unsigned int *)(cnt->res)));
		printf("Captured at interface %s : %d\n",argv[2],*((unsigned int *)(cnt2->res)));
	}
	printf("\nINJECT OK\n");

	return 0;
}
