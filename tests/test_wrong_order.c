#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <mapi.h>
#include "test.h"

int main(int argc , char** argv)
{
  int fd=-13141;
  int counter_all;
  char buffer[1024];
  int err_no, flag=0;
  
  
    
  if(mapi_connect(fd)<0){
      mapi_read_error(&err_no,buffer);
      printf("Error: %d - %s\n",err_no,buffer);
      if(err_no != 6141){
		printf("    Wrong ERRORCODE returned\n");
		flag = 1;	
      }

  }
DOT;  
  if(argc>1)
	  fd = mapi_create_flow(argv[1]);
  else{
	  printf("No args given using eth0 instead\n\n");
	  fd = mapi_create_flow("eth0");
	  return -1;
  }
  
DOT;  
  if(fd==-1){ /* invalid device */
     mapi_read_error(&err_no,buffer);
     printf("Error: %d - %s\n",err_no,buffer);
  }

DOT;  
 if(mapi_connect(fd)<0){
      mapi_read_error(&err_no,buffer);
      printf("Error: %d - %s\n",err_no,buffer);
 }
DOT;  
 counter_all=mapi_apply_function(fd,"PKT_COUNTER");
 
DOT;  
 if(counter_all==-1){
      mapi_read_error(&err_no,buffer);
      printf("Error: %d - %s\n",err_no,buffer);
      mapi_close_flow(fd);
      if(err_no != 7006){
		printf("          Wrong ERRORCODE returned\n");
		flag = 1;	
       }

  }
   
DOT;  
	mapi_close_flow(fd);
	
DOT;  
	if(!flag)
		printf("\nWrong Ordering error Checking OK\n");
	else 
		printf("\nWrong Ordering error Checking :FAILED:\n");


  return 0;
}









