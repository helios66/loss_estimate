#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "mapi.h"
#include "test.h"


int main(MAPI_UNUSED int argc, char *argv[])
{
	int fd;
	int fid;
	int res;
	mapi_function_info_t info;
	int err_no =0 , flag=0;
	char error[512];
	
	if(argc!=2){
		printf("\nWrong arguments\n");
		return -1;
	}
	if ((fd = mapi_create_flow(argv[1]))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((fid=mapi_apply_function(fd, "PKT_COUNTER"))<0){
	  	fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
	if((res = mapi_get_function_info(fd, fid, &info))<0){
	  	fprintf(stderr, "mapi_get_function_info failed for flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	

	/*
	 *Sanity check
	 */
	if(res >= 0){
		if(info.name!=NULL && strcmp("PKT_COUNTER" , info.name)!=0){
			fprintf(stderr, "WARNING: mapi_get_function_info failed\n");
		}
		else{
			printf("\nFunction fid=%d info:\n", fid);
			printf("\n\t name: %s", info.name);
			printf("\n\t libname: %s", info.libname);
			printf("\n\t devoid: %s", info.devtype);
			printf("\n\t pkts: %llu", -info.pkts);
			printf("\n\t passed_pkts: %llu", info.passed_pkts);
		}
	}
	else{
		printf("\nCould not apply function\n");
		return -1;
	}

	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;

	printf("\nmapi get_function_info function OK\n");
	/*
	 * Error checking
	 */

	fd =0;
	if ((fd = mapi_create_flow(argv[1]))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((fid=mapi_apply_function(fd, "PKT_COUNTER"))<0){
	  	fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	

	if( (res = mapi_get_function_info(12375, fid, &info)) !=0 ){
		mapi_read_error( &err_no, error);
		printf("Testing error case1: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6141){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;	
	if( (res = mapi_get_function_info(fd, 3123, &info)) !=0 ){
		mapi_read_error( &err_no, error);
		printf("Testing error case2: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6150){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;
	if( (res = mapi_get_function_info(fd, fid, NULL)) !=0 ){
		mapi_read_error( &err_no, error);
		printf("Testing error case3: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 7003){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;
	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

	/*
	 * Offline testing
	 */
	if ((fd = mapi_create_offline_flow("./tracefile" , MFF_PCAP))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((fid=mapi_apply_function(fd, "PKT_COUNTER"))<0){
	  	fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
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
	if((res = mapi_get_function_info(fd, fid, &info))<0){
	  	fprintf(stderr, "mapi_get_function_info failed for flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
	/*
	 *Sanity check
	 */
	if(res >= 0){
		if(info.name!=NULL && strcmp("PKT_COUNTER" , info.name)!=0){
			fprintf(stderr, "WARNING: mapi_get_function_info failed\n");
		}
		else{
			printf("\nFunction fid=%d info:\n", fid);
			printf("\n\t name: %s", info.name);
			printf("\n\t libname: %s", info.libname);
			printf("\n\t devoid: %s", info.devtype);
			printf("\n\t pkts: %llu", -info.pkts);
			printf("\n\t passed_pkts: %llu", info.passed_pkts);
		}
	}
	else{
		printf("\nCould not apply function\n");
		return -1;
	}

	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;
	/*
	 * Error checking
	 */

	fd =0;
	if ((fd = mapi_create_offline_flow("./tracefile" , MFF_PCAP))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((fid=mapi_apply_function(fd, "PKT_COUNTER"))<0){
	  	fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	

	if( (res = mapi_get_function_info(12375, fid, &info)) !=0 ){
		mapi_read_error( &err_no, error);
		printf("Testing error case4: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6141){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;	
	if( (res = mapi_get_function_info(fd, 3123, &info)) !=0 ){
		mapi_read_error( &err_no, error);
		printf("Testing error case5: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6150){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;
	if( (res = mapi_get_function_info(fd, fid, NULL)) !=0 ){
		mapi_read_error( &err_no, error);
		printf("Testing error case6: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 7003){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;
	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

	if(!flag)
		printf("\nMAPI get function info Error Checking OK\n");
	else 
		printf("\nMAPI get funcgion info Error Checking :FAILED:\n");
return 0;
}

