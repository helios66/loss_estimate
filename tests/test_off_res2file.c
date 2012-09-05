/*******************************************
 *
 *	offline Testing RES2FILE
 *
 *******************************************/


#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "mapi.h"
#include "mapi/res2file.h"
#include "mapi/pktinfo.h"
#include "test.h"

int main(MAPI_UNUSED int argc, char *argv[])
{
  int pkt_size,pkt_ts;
  int fd;
  int fid;
  mapi_flow_info_t info;
  char fids[128],types[10];
  FILE *f;
  char buf[1024],buf2[1024];
  int c;
  char format[128];
  int err_no =0 , flag=0;
  char error[512];
 
	if(argc!=2){ // just for uniformity reasons 
		  fprintf(stderr, "Wrong Arguments\n");
		  return -1;
	}
		  
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
	if((pkt_size=mapi_apply_function(fd,"PKTINFO",PKT_SIZE))<0){
	  	fprintf(stderr, "Could not apply PKTINFO to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
	if((pkt_ts=mapi_apply_function(fd,"PKTINFO",PKT_TS))<0){
	  	fprintf(stderr, "Could not apply PKTINFO to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;

  snprintf(fids,20,"%d@%d,%d@%d,%d@%d",fid,fd,pkt_size,fd,pkt_ts,fd);
  snprintf(types,10,"%d,%d,%d",R2F_ULLSTR,R2F_ULLSTR,R2F_ULLSEC);
  
	if((mapi_apply_function(fd,"RES2FILE",types,fids,"TEST","test.res","5s",1))<0){
	  	fprintf(stderr, "Could not apply RES2FILE to flow %d\n", fd);
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
  
  do
    {
      sleep(1);
      mapi_get_flow_info(fd,&info);
    }while(info.status!=FLOW_FINISHED);

	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}



  
  //Compare result files
  f=fopen("res2file.res","r");
  fread(buf,sizeof(char),1024,f);
  fclose(f);

  f=fopen("test.res","r");
  c=fread(buf2,sizeof(char),1024,f);
  fclose(f);

  if(memcmp(buf,buf2,c)!=0) {
    printf("Result files do not match\n");
//    return -1;
  }
  else  
	  printf("\nOffline RES2FILE OK\n");
  

  
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
	if((fid=mapi_apply_function(fd,"BYTE_COUNTER"))<0){
	  	fprintf(stderr, "Could not apply BYTE_COUNTER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
	memcpy(format,types,10);
	
	if(mapi_apply_function(fd,"RES2FILE",fids,format,"TEST", "ERROR_CASES", "-25s",1) <0){
		mapi_read_error( &err_no, error);
		printf("Testing error case1: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 7002){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;

	if(mapi_apply_function(fd,"RES2FILE",fids,format,"TEST", NULL, "5s",1) <0){
		mapi_read_error( &err_no, error);
		printf("Testing error case2: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6155){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}

	sprintf(fids, "\r\r\r\r\r\r\r\r\r\r\r1232@231,123123124 , @KALIMERA");
	
	if(mapi_apply_function(fd,"RES2FILE",fids,format,"TEST", "ERROR_CASES", "5s",1) <0){
		mapi_read_error( &err_no, error);
		printf("Testing error case3: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 7002){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;

	sprintf(format,"SKOUPIDIA" );

	if(mapi_apply_function(fd,"RES2FILE",fids,format,"TEST", "ERROR_CASES", "5s",1) <0){
		mapi_read_error( &err_no, error);
		printf("Testing error case4: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 7002){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}

	if(mapi_apply_function(fd,"RES2FILE",fids,format,"TEST", "ERROR_CASES", "5s",234) <0){
		mapi_read_error( &err_no, error);
		printf("Testing error case4: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 7011){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
	

DOT;
	if(!flag)
		printf("\nRes To File Error Checking OK\n");
	else 
		printf("\nRes To File Error Checking :FAILED:\n");

DOT;
	if(mapi_connect(fd)<0){
	 	fprintf(stderr, "Connecting to flow failed %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;	
        system("rm -f test.res* ERROR_CASES*");
	
  return 0;
}
