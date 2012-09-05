#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
/*******************************************
 *
 *	Testing PKT_COUNTER
 *
 *******************************************/


#include <stdio.h>
#include <unistd.h>
#include "../mapi.h"

int main(MAPI_UNUSED int argc, char *argv[])
{
	int fd;
	int fid,fid2,fid3,fid4;
	int *cnt,*cnt2,*cnt3,*cnt4;

	if(!argv[1])
	{
		printf("\nWrong arguments\n");
		
		return -1;
	}

	fd=mapi_create_flow(argv[1]);

	mapi_apply_function(fd, "BPF_FILTER", "tcp or udp");
	fid=mapi_apply_function(fd,"PKT_COUNTER");
	fid2=mapi_apply_function(fd,"BYTE_COUNTER");
	mapi_apply_function(fd,"TRACK_FTP");
	//mapi_apply_function(fd,"TRACK_GNUTELLA");
	fid3=mapi_apply_function(fd,"PKT_COUNTER");
	fid4=mapi_apply_function(fd,"BYTE_COUNTER");

	mapi_connect(fd);

	while (1) 
	{
		cnt=((struct dmapi_results*)mapi_read_results(fd,fid,MAPI_REF))->res[0].result;
		cnt2=((struct dmapi_results*)mapi_read_results(fd,fid2,MAPI_REF))->res[0].result;
		cnt3=((struct dmapi_results*)mapi_read_results(fd,fid3,MAPI_REF))->res[0].result;
		cnt4=((struct dmapi_results*)mapi_read_results(fd,fid4,MAPI_REF))->res[0].result;

		sleep(1);
		printf("Total packets: %d Total bytes: %d FTP packets: %d FTP bytes: %d\n",*cnt,*cnt2,*cnt3,*cnt4);
	}

	mapi_close_flow(fd);

	//printf("\nPKT_COUNTER OK\n");

	return 0;
}
