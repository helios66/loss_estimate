#ifndef _MAPI_ERRORS_H_ 
#define _MAPI_ERRORS_H_

typedef struct errstrct{ 
int err_no;  
char *desc; 	
} errorstruct;

#define PCAP_BPF_ERR 1025
#define PCAP_OPEN_ERR 1026
#define PCAP_OPEN_DEAD_ERR 1027
#define NICDRV_PTHR_ERR 1100
#define COMBO6_OPEN_ERR 1200
#define COMBO6_PTHR_ERR 1201
#define COMBO6_GET_OPTION_ERR 1202
#define COMBO6_GET_STU_STATS 1203
#define DAGDRV_OPEN_ERR 1300
#define DAGDRV_PTHR_ERR 1301
#define DAGDRV_MMAP_ERR 1302
#define DAGDRV_START_ERR 1303
#define VINDRV_PTHR_ERR 1400
#define VINDRV_OFF_ERR 1401
#define VINDRV_DEVID_NOT_FOUND 1401
#define DRV_OFF_ERR 1501
#define NAPATECHDRV_PTHR_ERR 1600
#define NAPATECHDRV_OPENCARD_ERR 1601
#define NAPATECHDRV_SHUTDOWN_FEEDS_ERR 1602
#define MDLIB_ERROR_NOT_FOUND 3073
#define MDLIB_INVALID_FLID 3074
#define MDLIB_SHM_ERR 3075
#define MDLIB_SEM_ERR 3076
#define MDLIB_TMPF_ERR 3077
#define MDLIB_INVALID_FUNCID 3078
#define MDLIB_FUNCTION_NOT_FOUND 3079
#define MDLIB_COULD_NOT_APPLY_FUNCT 3080
#define MDLIB_FLOW_ALREADY_ACTIVE 3081
#define MDLIB_NO_MODIFYING 3082
#define MDLIB_FILE_EXSISTS 3083
#define MAPID_NOT_AUTHENTICATED 3139
#define MAPID_NO_DRIVER 3200
#define MAPID_NO_FD 3201
#define MAPID_NO_DEVICE 3202
#define MDLIB_ETH_DLINK_ERR 3500
#define MDLIB_ETH_SYM_NOT_FOUND 3501
#define MDLIB_ETH_FILTER_ERR 3502
#define MDLIB_STRSEARCH_UNTERMINATED_PIPE_ERR 3503
#define MDLIB_STRSEARCH_DEPTH_LESS_THAN_PTRN_ERR 3504
#define MDLIB_STRSEARCH_NOT_A_VALID_SEARCH_STRING 3505
#define MCOM_UNKNOWN_ERROR 5121
#define MCOM_ERROR_ACK 5122
#define MCOM_SOCKET_ERROR 5123
#define MCOM_INIT_SOCKET_ERROR 5124
#define MAPI_SHUTTING_DOWN 6140
#define MAPI_INIT_ERROR 6141
#define MAPI_CONNECT 6142
#define MAPI_FLOW_NOT_CONNECTED 6143
#define MAPI_FUNCTION_NOT_FOUND 6144
#define MAPI_INVALID_FLOW 6145
#define MAPI_SHM_ERR 6146
#define MAPI_INVALID_FID_FUNCID 6147
#define MAPI_SEM_ERR 6148
#define MAPI_FLOW_INFO_ERR 6149
#define MAPI_FUNCTION_INFO_ERR 6150
#define MAPI_LIBRARY_LOAD_ERR 6151
#define MAPI_ERROR_GETTING_LIBPATH 6152
#define MAPI_ERROR_GETTING_LIBS 6153
#define MAPI_ERROR_GETTING_PATH 6154
#define MAPI_ERROR_FILE 6155
#define MAPI_ERROR_SEND_FD 6156
#define MAPI_DEVICE_INFO_ERR 6157
#define MFUNCT_INVALID_ARGUMENT 7000
#define MFUNCT_INVALID_ARGUMENT_1 7001
#define MFUNCT_INVALID_ARGUMENT_2 7002
#define MFUNCT_INVALID_ARGUMENT_3 7003
#define MFUNCT_INVALID_ARGUMENT_4 7004
#define MFUNCT_INVALID_ARGUMENT_5 7005
#define MFUNCT_COULD_NOT_APPLY_FUNCT 7006
#define MFUNCT_COULD_NOT_INIT_FUNCT 7007
#define MFUNCT_SEM_ERROR 7008
#define MFUNCT_NOT_SUPPORTED 7009
#define MFUNCT_INVALID_ARGUMENT_DESCRIPTOR 7010
#define MFUNCT_INVALID_ARGUMENT_6 7011
#define ADMCTRL_MEM_ERROR 8000
#define ADMCTRL_NO_AUTHDATA 8001
#define ADMCTRL_COMM_FAILURE 8002
#define ADMCTRL_AUTH_FAILED 8003
#define MAPI_STATS_ERROR 8004
#define MAPID_MEM_ALLOCATION_ERROR 3084
#endif

