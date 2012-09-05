#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/time.h>
#include <linux/if_ether.h>
#include <unistd.h>
#include <mapi.h>
#include "test.h"
 
int counter =0;
void callback(const struct mapipkt*);

void callback(const struct mapipkt *pkt){
    const unsigned char *p; 
    int j = 0;

    if(pkt==NULL){
		counter=0;
		return;
    }
    p = &pkt->pkt;
printf("in callback\n");
    p+=(ETH_HLEN+12);
    printf("src IP: ");
    for (j = 0; j < 4; j++) {
      printf("%03d", *p++);
      if (j<3)
        printf(".");
    }
    printf(" dst IP: ");
    for (j = 0; j < 4; j++) {
      printf("%03d", *p++);
      if (j<3)
        printf(".");
      else
        printf("\n");
    }
counter++;
usleep(20);
 return;
}

int main(int argc , char* argv[])
{
  int fd;
  int bufid;
  int err_no =0 , flag=0;
  char error[512];


  if(argc !=2){
	    fprintf(stderr,"Wrong arguments\n");
	    return -1;
  }
  
  if ((fd = mapi_create_flow(argv[1]))<0){
	fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
	mapi_read_error( &err_no, error);
	fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
	return -1;
  }
DOT;

  if ((bufid=mapi_apply_function(fd,"TO_BUFFER", 0))<0){
	fprintf(stderr, "Could not apply function TO_BUFFER\n");
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
	if(mapi_loop(fd, bufid, 20, &callback) <0){
	  	fprintf(stderr, "Could not apply mapi_loop to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
	/*
	 *Sanity check
	 */
	if(counter!=20)
		fprintf(stderr, "WARNING: mapi_loop called less times than excpected %d\n" , counter);
	else
  		printf("\nmapi_loop OK\n");

DOT;	
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

  fd=bufid =0;
  
DOT;  
  if((fd = mapi_create_flow(argv[1]))<0){
	fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
  	mapi_read_error( &err_no , error);
	fprintf(stderr,"Mapi Create flow failed: Errorcode :%d description: %s \n" ,err_no, error);
	return -1;
  }
DOT;
  if((bufid=mapi_apply_function(fd,"TO_BUFFER", 0))<0){
	fprintf(stderr, "Could not apply function TO_BUFFER\n");
	mapi_read_error( &err_no , error);
	fprintf(stderr,"TO_BUFFER failed: Errorcode :%d description: %s \n" ,err_no, error);
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
  if(mapi_loop(-123,bufid,50,&callback)<0  ){
  	mapi_read_error( &err_no , error);
	printf("Test error case1: Errorcode :%d description: %s \n" ,err_no, error);
	if(err_no != 6147){
		printf("          Wrong ERRORCODE returned\n");
		flag = 1;	
	}
  }
DOT;
  if(mapi_loop(fd,-12348,50,&callback)<0  ){
  	mapi_read_error( &err_no , error);
	printf("Test error case2: Errorcode :%d description: %s \n" ,err_no, error);
	if(err_no != 6147){
		printf("          Wrong ERRORCODE returned\n");
		flag = 1;	
	}
  }
DOT;  
  if(mapi_loop(fd,bufid,50,NULL)<0  ){
  	mapi_read_error( &err_no , error);
	printf("Test error case3: Errorcode :%d description: %s \n" ,err_no, error);
	if(err_no != 7004){
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
 * Offline checking
 */
  if ((fd = mapi_create_offline_flow("./tracefile",MFF_PCAP))<0){
	fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
	mapi_read_error( &err_no, error);
	fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
	return -1;
  }
DOT;

  if ((bufid=mapi_apply_function(fd,"TO_BUFFER", 0))<0){
	fprintf(stderr, "Could not apply function TO_BUFFER\n");
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
counter=0;
	if(mapi_loop(fd, bufid, 893, &callback) <0){
	  	fprintf(stderr, "Could not apply mapi_loop to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

	/*
	 *Sanity check
	 */
	if(counter!=893)
		fprintf(stderr, "WARNING: mapi_loop called less times than excpected %d\n" , counter);
	else
		printf("mapi_loop offline test OK\n");
	

DOT;	
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

  fd=bufid =0;
  
DOT;  
  if((fd = mapi_create_offline_flow("./tracefile" ,MFF_PCAP))<0){
	fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
  	mapi_read_error( &err_no , error);
	fprintf(stderr,"Mapi Create flow failed: Errorcode :%d description: %s \n" ,err_no, error);
	return -1;
  }
DOT;
  if((bufid=mapi_apply_function(fd,"TO_BUFFER", 0))<0){
	fprintf(stderr, "Could not apply function TO_BUFFER\n");
	mapi_read_error( &err_no , error);
	fprintf(stderr,"TO_BUFFER failed: Errorcode :%d description: %s \n" ,err_no, error);
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
  if(mapi_loop(-123,bufid,50,&callback)<0  ){
  	mapi_read_error( &err_no , error);
	printf("Test error case1: Errorcode :%d description: %s \n" ,err_no, error);
	if(err_no != 6147){
		printf("          Wrong ERRORCODE returned\n");
		flag = 1;	
	}
  }
DOT;
  if(mapi_loop(fd,-12348,50,&callback)<0  ){
  	mapi_read_error( &err_no , error);
	printf("Test error case2: Errorcode :%d description: %s \n" ,err_no, error);
	if(err_no != 6147){
		printf("          Wrong ERRORCODE returned\n");
		flag = 1;	
	}
  }


  
  if(!flag)
	printf("\nMAPI Loop Error Checking OK\n");
  else 
	printf("\nMAPI Loop Flow Error Checking :FAILED:\n");
	
  return 0;
}
