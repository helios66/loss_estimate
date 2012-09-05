#include <stdio.h>
#include <stdlib.h>
#include "mapi.h"

int main(MAPI_UNUSED int argc, char *argv[])
{
	int fd;
	int fid;
	mapi_results_t* cn;

	if(!argv[1])
	{
		printf("\nWrong arguments\n");
		return -1;
	}

	fd = mapi_create_flow(argv[1]);

	if(mapi_create_flow("hda") < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error( &err_no,err_buffer);
		printf("1. Error: %d - %s\n", err_no, err_buffer);
	}

	if(mapi_close_flow(15) < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error( &err_no,err_buffer);
		printf("2. Error: %d - %s\n", err_no, err_buffer);
	}
	
	if(mapi_connect(15) < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error( &err_no, err_buffer);
		printf("3. Error: %d - %s\n", err_no, err_buffer);
	}
		
	if((fid=mapi_apply_function(15, "PKT_COUNTER")) < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error( &err_no, err_buffer);
		printf("4. Error: %d - %s\n", err_no, err_buffer);
	}
	
	cn=mapi_read_results(fd, 43);
	if((cn) == NULL)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error( &err_no, err_buffer);
		printf("5. Error: %d - %s\n", err_no, err_buffer);
	}
		
	if(mapi_create_offline_flow(argv[2], 32) < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error( &err_no, err_buffer);
		printf("6. Error: %d - %s\n", err_no, err_buffer);
	}
	mapi_close_flow(fd);

	if(mapi_get_next_pkt(fd, 43) == NULL)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error( &err_no, err_buffer);
		printf("7. Error: %d - %s\n", err_no, err_buffer);
	}
	
	fd = mapi_create_flow(argv[1]);
	
	if((fid=mapi_apply_function(fd, "PKT_COUNTER")) < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error( &err_no, err_buffer);
		printf("8. Error: %d - %s\n", err_no, err_buffer);
	}
	
	if(mapi_get_next_pkt(fd, fid) == NULL)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error( &err_no, err_buffer);
		printf("9. Error: %d - %s\n", err_no, err_buffer);
	}

	mapi_close_flow(fd);

	return 0;
}
