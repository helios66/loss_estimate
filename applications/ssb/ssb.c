
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <mapi.h>
#include <res2file.h>

#define INTERVALS 3

int currentfd[INTERVALS+2],nextfd[INTERVALS+2];

time_t getNextInterval() {
  time_t t;
  int s;

  time(&t);

  t+=5; //Add 5 seconds to make sure that the flow has time to start
  s=t%300;

  return t+(300-s);
  
}

void createFlows(char *dev,int ifindex,char *start, char *stop, char *path) {
  int byte,pkt,stats1[INTERVALS],stats2[INTERVALS];
  int i;
  char str[256],*space;
  char fids[128],types[128];
  char intervals[4][20]={"1s","100ms","10ms"};

  for(i=0;i<INTERVALS;i++) {
    nextfd[i]=mapi_create_flow(dev);
    mapi_apply_function(nextfd[i],"INTERFACE",ifindex);
    mapi_apply_function(nextfd[i],"STARTSTOP",start,stop);
    byte=mapi_apply_function(nextfd[i],"BYTE_COUNTER");
    pkt=mapi_apply_function(nextfd[i],"PKT_COUNTER");
    stats1[i]=mapi_apply_function(nextfd[i],"STATS",nextfd[i],byte,intervals[i]);
    stats2[i]=mapi_apply_function(nextfd[i],"STATS",nextfd[i],pkt,intervals[i]);
    mapi_connect(nextfd[i]);
  }

  nextfd[INTERVALS]=mapi_create_flow(dev);
  mapi_apply_function(nextfd[INTERVALS],"INTERFACE",ifindex);
  mapi_apply_function(nextfd[INTERVALS],"STARTSTOP",start,stop);
  byte=mapi_apply_function(nextfd[INTERVALS],"BYTE_COUNTER");
  pkt=mapi_apply_function(nextfd[INTERVALS],"PKT_COUNTER");
  mapi_connect(nextfd[INTERVALS]);

  nextfd[INTERVALS+1]=mapi_create_flow(dev);
  mapi_apply_function(nextfd[INTERVALS+1],"INTERFACE",ifindex);
  mapi_apply_function(nextfd[INTERVALS+1],"STARTSTOP",start,"+400s");
 snprintf(fids,128,"%d@%d,%d@%d,%d@%d,%d@%d,%d@%d,%d@%d,%d@%d,%d@%d",
	  byte,nextfd[INTERVALS],pkt,nextfd[INTERVALS],
	  stats1[0],nextfd[0],stats2[0],nextfd[0],stats1[1],nextfd[1],stats2[1],nextfd[1],
	  stats1[2],nextfd[2],stats2[2],nextfd[2]);
 snprintf(types,128,"%d,%d,%d,%d,%d,%d,%d,%d",R2F_ULLSTR,R2F_ULLSTR,R2F_STATS,R2F_STATS,R2F_STATS,R2F_STATS,R2F_STATS,R2F_STATS);
  sprintf(str,"%s/tmp_%s.txt",path,start);
  space=strchr(str,' ');
  *space='_';

  mapi_apply_function(nextfd[INTERVALS+1],"RES2FILE",types,fids,"bytes1s packets1s bytes100ms packets100ms bytes10ms packets10ms",str,"300s",1);
  mapi_connect(nextfd[INTERVALS+1]);

}

void renameFile(char *start,char *path) {
  char str[80],str2[80],*space;

  sprintf(str,"%s/tmp_%s.txt",path,start);
  space=strchr(str,' ');
  *space='_';

  sprintf(str2,"%s/%s.txt",path,start);
  space=strchr(str2,' ');
  *space='_';

  rename(str,str2);
}

int
main(int argc, char **argv) {
  time_t start,stop,stop2,now,sl;
  struct tm *t;
  int ifindex,i;
  char startstr[64],stopstr[64],stopstr2[64];
  char str[64];

  if(argc<4) {
    printf("Usage: ssb <device> <ifindex> <result path>\n");
    exit(-1);
  }

  sscanf(argv[2],"%d",&ifindex);

  //Find start time for next 5 minute time interval
  start=getNextInterval();
  stop=start+300;
  stop2=stop+300;
  
  t=localtime(&start);
  strftime(startstr,64,"%Y-%m-%d %H:%M:%S",t);
  t=localtime(&stop);
  strftime(stopstr,64,"%Y-%m-%d %H:%M:%S",t);
  t=localtime(&stop2);
  strftime(stopstr2,64,"%Y-%m-%d %H:%M:%S",t);

  createFlows(argv[1],ifindex,startstr,stopstr,argv[3]);
  for(i=0;i<=INTERVALS+1;i++)
    currentfd[i]=nextfd[i];
  createFlows(argv[1],ifindex,stopstr,stopstr2,argv[3]);

  time(&now);
  sl=start-now+310;
  while(1) {
    time(&start);
    t=localtime(&start);
    strftime(str,64,"%Y-%m-%d %H:%M:%S",t);
    sleep(sl);
    for(i=INTERVALS+1;i>=0;i--) {
      mapi_close_flow(currentfd[i]);
      currentfd[i]=nextfd[i];
    }
    renameFile(startstr,argv[3]);
    strcpy(startstr,stopstr);
    start=stop;
    stop+=300;
    stop2+=300;
    time(&now);
    sl=start-now+310;
    t=localtime(&stop);
    strftime(stopstr,64,"%Y-%m-%d %H:%M:%S",t);
    t=localtime(&stop2);
    strftime(stopstr2,64,"%Y-%m-%d %H:%M:%S",t);
    createFlows(argv[1],ifindex,stopstr,stopstr2,argv[3]);    
  }

}
