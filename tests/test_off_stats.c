/*******************************************
 *
 *	offline Testing STATS
 *
 *******************************************/


#include <stdio.h>
#include <unistd.h>
#include "mapi.h"
#include "mapi/stats.h"
#include "mapi/pktinfo.h"
#include "test.h"

int main(MAPI_UNUSED int argc, char *argv[])
{
  int size;
  int fd;
  int fid;
  mapi_flow_info_t info;
  mapi_results_t* res;
  stats_t *stats;
  int err_no =0 , flag=0;
  char error[512];
  
  if(!argv[1])
    {
      printf("\nWrong arguments\n");
      
      return -1;
    }
  
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

	if((size=mapi_apply_function(fd,"PKTINFO",PKT_SIZE))<0){
	  	fprintf(stderr, "Could not apply PKTINFO to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
	if((fid=mapi_apply_function(fd,"STATS",fd,size,"0"))<0){
	  	fprintf(stderr, "Could not apply STATS to flow %d\n", fd);
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
  
  do {
    sleep(1);
    mapi_get_flow_info(fd,&info);
  } while(info.status!=FLOW_FINISHED);
  
  res = mapi_read_results(fd,fid);
  stats = (stats_t*)res->res;
/*
 * Sanity Checks
 */
  if(stats->count!=893 || stats->sum!=283464.0 ||
     stats->sum2!=309175572.0 || stats->min!=42.0 ||
     stats->max!=1514) {
    printf("Wrong values\n");
    return -1;
  }
 	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;	
 
  
  printf("Offline STATS OK\n");
/*
 * Error checking test postponed till correcting a
 */
	if ((fd = mapi_create_offline_flow("./tracefile" , MFF_PCAP))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;

	if((size=mapi_apply_function(fd,"PKTINFO",PKT_SIZE))<0){
	  	fprintf(stderr, "Could not apply PKTINFO to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	

  fid=mapi_apply_function(fd,"STATS",1234343,size,"0");
  if (fid<0){
  	mapi_read_error( &err_no, error);
	printf("Testing error case1: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 7001){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
  }
DOT;  
  fid=mapi_apply_function(fd,"STATS",fd,-12352,"0");
  if (fid<0){
  	mapi_read_error( &err_no, error);
	printf("Testing error case2: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 7001){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
  }
DOT;
  if(!flag)
		printf("\nTest offline stats Error Checking OK\n");
  else 
		printf("\nTest offline stats Error Checking :FAILED:\n");
  	
  if(mapi_close_flow(fd)<0){
	fprintf(stderr,"Close flow failed\n");
	mapi_read_error( &err_no, error);
	fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
	return -1;
  }
DOT;	

return 0;
}
