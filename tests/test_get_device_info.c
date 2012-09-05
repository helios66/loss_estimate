#include <stdio.h>
#include <unistd.h>
#include "mapi.h"
#include "test.h"

int main(MAPI_UNUSED int argc, char *argv[])
{
	int fd, ok;
	mapi_flow_info_t info;
	mapi_device_info_t device_info;
	//mapi_device_info_t device_info[3];	//e.g. for network flow consists of 3 monitoring devices
	int err_no =0;
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
	printf("\n\t devid = %d", info.devid);	
	printf("\n");
DOT;
	if((ok = mapi_get_device_info(info.devid, &device_info))<0){
	//if((ok = mapi_get_device_info(info.devid, device_info))<0){  //In case of 3 devices
	 	fprintf(stderr, "Getting device info failed on devid:%d\n", info.devid);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

	printf("\ndevice info : ");
	printf("\n\t id = %d", device_info.id);
	printf("\n\t device = %s", device_info.device);
	printf("\n\t name: %s", device_info.name);
	printf("\n\t alias = %s", device_info.alias);
	printf("\n\t description = %s", device_info.description);
	printf("\n\t link_speed = %d", device_info.link_speed);
	printf("\n\t mpls = %d", device_info.mpls);
	printf("\n\t vlan = %d", device_info.vlan);
	
	printf("\n");

/*  
    // In case of 3 monitoring device in the DIMAPI flow
 
	printf("\ndevice info : Device 1 ");
	printf("\n\t id = %d", device_info[0].id);
	printf("\n\t device = %s", device_info[0].device);
	printf("\n\t name: %s", device_info[0].name);
	printf("\n\t alias = %s", device_info[0].alias);
	printf("\n\t description = %s", device_info[0].description);
	printf("\n\t link_speed = %d", device_info[0].link_speed);
	printf("\n\t mpls = %d", device_info[0].mpls);
	printf("\n\t vlan = %d", device_info[0].vlan);
	
	printf("\n");

	printf("\ndevice info : Device 2 ");
	printf("\n\t id = %d", device_info[1].id);
	printf("\n\t device = %s", device_info[1].device);
	printf("\n\t name: %s", device_info[1].name);
	printf("\n\t alias = %s", device_info[1].alias);
	printf("\n\t description = %s", device_info[1].description);
	printf("\n\t link_speed = %d", device_info[1].link_speed);
	printf("\n\t mpls = %d", device_info[1].mpls);
	printf("\n\t vlan = %d", device_info[1].vlan);
	
	printf("\n");

	printf("\ndevice info : Device 3 ");
	printf("\n\t id = %d", device_info[2].id);
	printf("\n\t device = %s", device_info[2].device);
	printf("\n\t name: %s", device_info[2].name);
	printf("\n\t alias = %s", device_info[2].alias);
	printf("\n\t description = %s", device_info[2].description);
	printf("\n\t link_speed = %d", device_info[2].link_speed);
	printf("\n\t mpls = %d", device_info[2].mpls);
	printf("\n\t vlan = %d", device_info[2].vlan);
	
	printf("\n");
*/

	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

return 0;	
}	
