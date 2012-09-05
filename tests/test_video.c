#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "mapi.h"
#include "mapi/pktinfo.h"
#include "mapi/res2file.h"
#define DEBUGGING

int readTrace(char filename[],long* videoports,unsigned short videoports_len);
int main(int argc, char *argv[])
{
        
        
        unsigned short  sources=1;
        long inputports[1];
        int iterator;

#ifdef DEBUGGING
        printf("\n *** DEBUGGING ***\n\n");
#endif
        if(argc<=2)
        {
                printf("\nUsage: dataFromVideos <tracename> <...List of videoports...>\n");
                
                return -1;
        }
        
        for(iterator=0;iterator<sources;iterator++)
        {
                inputports[iterator%sources]=atol(argv[(iterator+2)]);
        }
        readTrace(argv[1],&inputports[0],sources);
        return 0;
}

int readTrace(char filename[],long* videoports,unsigned short videoports_len){


        int fd,size,gap,rate,udpdport,bytes,streams,ts;
        char portfilter[10],file_port[5];
        char *devicename;
        char fids_data[20],fids_rate[20],types_data[20],types_rate[20];
        //const int VIDEO=0,VIDEO_CTRL=1,AUDIO=2,AUDIO_CTRL=3;
        char file_start[256],outfile_data[256],outfile_rate[256];
        mapi_flow_info_t info;
        int videostream=0;
        int fd_stream[4];
        char data_end[]=".packets";
        char rate_end[]=".rate";
        int filename_len;
        int i, j;

        streams=4*videoports_len;
        
        memset(file_start,'\0',256);
        memset(outfile_data,'\0',256);
        memset(outfile_rate,'\0',256);
	filename_len = strlen(filename)-5;
        strncpy(file_start,filename,filename_len);
        file_start[filename_len]='\0';
        
        strcat(outfile_data,file_start);
        strcat(outfile_data,data_end);
        strcat(outfile_rate,file_start);
        strcat(outfile_rate,rate_end);
	devicename = mapi_create_offline_device(filename,MFF_PCAP);		
	fd=mapi_create_flow(devicename);
        mapi_apply_function(fd, "BPF_FILTER","udp and src net 10.0");
        size=mapi_apply_function(fd,"PKTINFO",PKT_SIZE);
        printf("size = %d\n",size);
		ts=mapi_apply_function(fd,"PKTINFO",PKT_TS);
        gap=mapi_apply_function(fd,"GAP");
        rate=mapi_apply_function(fd,"STATS",fd,size,"0");
        bytes=mapi_apply_function(fd,"BYTE_COUNTER");
        snprintf(fids_data,20,"%d@%d,%d@%d,%d@%d",gap,fd,size,fd,ts,fd);
        printf("%d@%d,%d@%d,%d@%d\n",gap,fd,size,fd,ts,fd);
        snprintf(types_data,20,"%d,%d,%d",R2F_ULLSEC,R2F_ULLSTR,R2F_ULLSEC);
        snprintf(fids_rate,20,"%d",rate);
        snprintf(types_rate,20,"%d",R2F_STATS);

        mapi_apply_function(fd,"RES2FILE",types_data,fids_data,"",outfile_data,"0");
#ifdef DEBUGGING
        printf("\n\tWrong Output:  \n");
#endif          
	mapi_apply_function(fd,"RES2FILE",types_rate,fids_rate,"",outfile_rate,"4s");//TODO: Fault here
        mapi_connect(fd);
	mapi_start_offline_device(devicename);
        do
        {       
               sleep(1);
               mapi_get_flow_info(fd, &info);
        }while(info.status!=FLOW_FINISHED);
        mapi_close_flow(fd);
		mapi_delete_offline_device(devicename);

        
        devicename = mapi_create_offline_device(filename,MFF_PCAP);	
        for( j = 0;j<streams;j++)
                fd_stream[j]=mapi_create_flow(devicename);
		

        udpdport=0;
        for( i=0;i<streams;i++)
        {
                if((i%4)==0)
                        udpdport=videoports[videostream++];
                else
                        udpdport++;

                sprintf(portfilter,"udp dst port %d",udpdport);
                sprintf(file_port,"%d",udpdport);
                memset(outfile_data,'\0',256);
                strcat(outfile_data,file_start);
                strcat(outfile_data,"_");
                strcat(outfile_data,file_port);
                strcat(outfile_data,data_end);
                memset(outfile_rate,'\0',256);
                strcat(outfile_rate,file_start);
                strcat(outfile_rate,"_");
                strcat(outfile_rate,file_port);
                strcat(outfile_rate,rate_end);
             

                mapi_apply_function(fd_stream[i], "BPF_FILTER","udp and src net 10.0");
                mapi_apply_function(fd_stream[i],"BPF_FILTER",portfilter);
                size=mapi_apply_function(fd_stream[i],"PKTINFO",PKT_SIZE);
                ts=mapi_apply_function(fd_stream[i],"PKTINFO",PKT_TS);
                gap=mapi_apply_function(fd_stream[i],"GAP");
                rate=mapi_apply_function(fd_stream[i],"STATS",fd_stream[i],size,0);
                snprintf(fids_data,20,"%d@%d,%d@%d,%d@%d",gap,fd_stream[i],size,fd_stream[i],ts,fd_stream[i]);
                snprintf(types_data,20,"%d,%d,%d",R2F_ULLSEC,R2F_ULLSTR,R2F_ULLSEC);
//              sprintf(fids_rate,"%llu",rate);//TODO: copy from above
                mapi_apply_function(fd_stream[i],"RES2FILE",types_data,fids_data,"",outfile_data,"0");
//              mapi_apply_function(fd_stream[i],"RES2FILE",R2F_STATS,fids_rate,"",outfile_rate,"1s");//TODO copy from above
        		
        		mapi_connect(fd_stream[i]);
		}

        mapi_start_offline_device(devicename);
        for( i=0;i<streams;i++)
		{
			do
       		{       
        	        mapi_get_flow_info(fd_stream[1], &info);
    	    }
			while(info.status!=FLOW_FINISHED);

        	mapi_close_flow(fd_stream[i]);
		}
		mapi_delete_offline_device(devicename);	

        return 0;
        
}
