#include <stdio.h>
#include <unistd.h>
#include "mapi.h"
#include "test.h"

int main(MAPI_UNUSED int argc, char *argv[])
{
	int fd, ok;
	mapi_flow_info_t info;
	int err_no =0 , flag=0;
	char error[512];

	if(!argv[1])
	{
		printf("\nwrong arguments\n");

		return -1;
	}
	
	if ((fd = mapi_create_flow(argv[1]))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((ok = mapi_apply_function(fd, "PKT_COUNTER"))<0){
		fprintf(stderr,"Could not apply function PKT_COUNTER\n");  
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;	
	if((ok = mapi_apply_function(fd, "BYTE_COUNTER"))<0){
		fprintf(stderr,"Could not apply function BYTE_COUNTER\n");  
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((ok = mapi_apply_function(fd, "PKT_COUNTER"))<0){
		fprintf(stderr,"Could not apply function PKT_COUNTER\n");  
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((ok = mapi_apply_function(fd, "BYTE_COUNTER"))<0){
		fprintf(stderr,"Could not apply function BYTE_COUNTER\n");  
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((ok = mapi_apply_function(fd, "PKT_COUNTER"))<0){
		fprintf(stderr,"Could not apply function PKT_COUNTER\n");  
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((ok = mapi_apply_function(fd, "BYTE_COUNTER"))<0){
		fprintf(stderr,"Could not apply function BYTE_COUNTER\n");  
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;	
	if((ok = mapi_apply_function(fd, "PKT_COUNTER"))<0){
		fprintf(stderr,"Could not apply function PKT_COUNTER\n");  
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((ok = mapi_apply_function(fd, "BYTE_COUNTER"))<0){
		fprintf(stderr,"Could not apply function BYTE_COUNTER\n");  
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((ok = mapi_apply_function(fd, "PKT_COUNTER"))<0){
		fprintf(stderr,"Could not apply function PKT_COUNTER\n");  
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((ok = mapi_apply_function(fd, "BYTE_COUNTER"))<0){
		fprintf(stderr,"Could not apply function BYTE_COUNTER\n");  
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;	
	if(mapi_connect(fd)<0){
	 	fprintf(stderr, "Connecting to flow failed %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
	if((ok = mapi_get_flow_info(fd, &info))<0){
	 	fprintf(stderr, "Getting flow info failed on fd:%d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	printf("\nflow info : ");
	printf("\n\t uid = %d", info.uid);
	printf("\n\t device = %s", info.device);
	printf("\n\t num_functions: %u", info.num_functions);
	printf("\n\t start = %lu", info.start);
	printf("\n\t end = %lu", info.end);
	
	printf("\n");
/*
 * Sanity checks
 */
   if(info.num_functions != 10){
   	fprintf(stderr, "WARNING: Sanity check failed %d functions found\n" , info.num_functions);
   }
	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;
	/*
	 * Wrong argument error checking 
	 */
	
	fd =0;
	if(mapi_get_flow_info(fd, &info)<0){
		mapi_read_error( &err_no, error);
		printf("Testing error case0. Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6145){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;

	if ((fd = mapi_create_flow(argv[1]))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if(mapi_get_flow_info(fd, NULL)<0){
		mapi_read_error( &err_no, error);
		printf("Testing error case1. Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 7002){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;
	if(mapi_get_flow_info(12345, &info)<0){
		mapi_read_error( &err_no, error);
		printf("Testing error case2. Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6145){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;
	if ((fd = mapi_create_offline_flow("./tracefile" , MFF_PCAP))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((ok = mapi_apply_function(fd, "PKT_COUNTER"))<0){
		fprintf(stderr,"Could not apply function PKT_COUNTER\n");  
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;	
	if((ok = mapi_apply_function(fd, "BYTE_COUNTER"))<0){
		fprintf(stderr,"Could not apply function BYTE_COUNTER\n");  
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((ok = mapi_apply_function(fd, "PKT_COUNTER"))<0){
		fprintf(stderr,"Could not apply function PKT_COUNTER\n");  
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((ok = mapi_apply_function(fd, "BYTE_COUNTER"))<0){
		fprintf(stderr,"Could not apply function BYTE_COUNTER\n");  
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if(mapi_connect(fd)<0){
	 	fprintf(stderr, "Connecting to flow failed %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
info.num_functions=0;

DOT;	
	if((ok = mapi_get_flow_info(fd, &info))<0){
	 	fprintf(stderr, "Getting flow info failed on fd:%d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
/*
 * Sanity checks
 */
   if(info.num_functions != 4){
   	fprintf(stderr, "WARNING: Sanity check failed %d functions found\n" , info.num_functions);
   }
	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;

	if(!flag)
		printf("\nGet Flow Info Error Checking OK\n");
	else 
		printf("\nGet Flow Info Error Checking :FAILED:\n");

	return 0;
	
}	
