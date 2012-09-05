#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <mapi.h>

void usage(void) {
  printf("Usage: mapiinfo [-dlfu]\n\n\t-d show available devices\n\t-l show available libraries\n\t-f Show available libraries and functions in each library\n\t-o Show all active flows\n\t-u Show all active flows and list applied functions\n\n");
  exit(0);
}

void printDevices() {
  int id=0;
  mapi_device_info_t info;
  printf("\nID device driver alias description\n");
  while(mapi_get_next_device_info(id,&info)==0) {
    id=info.id;
    printf("%d %s %s %s %s\n",info.id,info.device,info.name,info.alias,info.description);
  }
  
}

void printLibs(functs) {
	int id=-1,fid;
	mapi_lib_info_t info;
	mapi_libfunct_info_t finfo;
	
	printf("ID\tName\t# functions\n");
	while(mapi_get_next_library_info(id,&info)==0) {
		printf("%d\t%s\t%d\n",info.id,info.libname,info.functs);
		if(functs) {
			fid=-1;
			while(mapi_get_next_libfunct_info(info.id,fid++,&finfo)==0)
				printf("\t\t%s(%s)\n",finfo.name,finfo.argdescr);
		}
		id++;
	}
	if(functs) {
		printf("\ns=string\t");
		printf("i=int\t");
		printf("r=reference to flow\t");
		printf("f=reference to function\t");
		printf("c=single character\t");
		printf("l=unsigned long long\t");
		printf("w=file name of writable file\n");
	}
		
}

void printFlows(functs) {
  int fd=0,fid;
  mapi_flow_info_t info;
  mapi_function_info_t finfo;

  printf("\nUID  fd  Device    Functions  Start\n");

  while(mapi_get_next_flow_info(fd,&info)==0) {
    fd=info.fd;
    printf("%d   %d  %s  %d   %lu\n",info.uid,info.fd,info.device,info.num_functions,info.start);
    if(functs) {
      printf("\tFID  Name   Library  Devtype\n");
      fid=0;
      while(mapi_get_next_function_info(fd,fid,&finfo)==0) {
	fid=finfo.fid;
	printf("\t%d %s %s %s\n",finfo.fid,finfo.name,finfo.libname,finfo.devtype);
      }
    }
  }

}

int main(int argc, char *argv[]) {
  int opt;
  int devices=0, libs=0, libfuncts=0, flows=0, flowfuncts=0;

  if(argc==1)
    usage();

  while((opt = getopt(argc,argv,"dlfou"))!=EOF) {
    switch(opt) {
    case 'd' :
      devices=1;
      break;
    case 'l' :
      libs=1;
      break;
    case 'f' :
      libfuncts=1;
      break;
    case 'o' :
      flows=1;
      break;
    case 'u' :
      flowfuncts=1;
      break;
    default:
      usage();
    }
  }

  if(devices)
    printDevices();

  if(flows || flowfuncts)
    printFlows(flowfuncts);

  if(libs || libfuncts) {
  	printLibs(libfuncts);
    exit(0);
  }

  return 0;
}
