#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <pcap.h>
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"
#include "mapiipc.h"
#include "anonymization.h"
#include "prefix_preserving_map.h"
#include "../extraflib/cooking.h"
#include "mapi_errors.h"
#include "debug.h"

#include "names.h"
extern char *anonnames[];

struct anonymize_data {
	int protocol;
	int field;
	int function;
	char *marshalledBuffer;
	int hash_algorithm;
	int padding_behavior;
	int distribution_type;
	int median;
	int standard_deviation;
	int seed;
	int pattern_type;
	char *pattern;
	char *regexp;
	int num_of_matches;
	char **replaceVector;
	struct cooking_data *flow;
	void *decoded_packet;
	mapidflib_function_instance_t *first_anon_instance;
	int fd;
};

int can_field_be_applied_to_protocol(int protocol,int field);
int can_field_be_applied_to_function(int anonymization_function,int field); 
void anonymize_field(int protocol, int field, int function,mapipacket *packet,struct anonymize_data *params); 
void init_mapping_tables();
void swap(unsigned char *a,unsigned char *b);
void checkSwap(unsigned char *field_pointer,int field); 
int anonymize_stream(mapidflib_function_instance_t *instance,struct cooking_data *flow,struct anonymize_data *params,mapid_pkthdr_t* pkt_head, unsigned char *mod_pkt); 
void anonymize_reordering(struct cooking_data *flow); 


extern void hide_addr(unsigned char *raw_addr);
extern int reg_exp_substitute(unsigned char *field, int len, char *regular_expression, char **replacement_vector, int num_of_matches,mapipacket *p,int total_len,unsigned char *packet_end);

/* mapping table for fields */

mapNode *ipMappingTable[MAPPING_ENTRIES]; int ip_count=1;
mapNode *portsMappingTable[MAPPING_ENTRIES]; int ports_count=1;
mapNode *generalMapping32Table[MAPPING_ENTRIES]; int general32_count=1;
mapNode *generalMapping16Table[MAPPING_ENTRIES]; int general16_count=1;
mapNode *generalMapping8Table[MAPPING_ENTRIES]; int general8_count=1;

/******FUNCTION STUFF*******/

///////////////////////////////////
struct mapidlibflow *tmp_flow;

int can_field_be_applied_to_protocol(int protocol,int field) {
	if(field==PAYLOAD) //common to all protocols
		return 1;
	
	switch(protocol) {
		case IP: 
			if((field<PAYLOAD || field>FRAGMENT_OFFSET) && field != FLOW)
				return 0;
			break;
		case TCP:
			if(field<PAYLOAD || field>TCP_OPTIONS)
				return 0;
			break;
		case UDP:
			if((field<PAYLOAD || field>DST_PORT) && field!=UDP_DATAGRAM_LENGTH)
				return 0;
			break;
		case ICMP:
			if(field<PAYLOAD || (field>FRAGMENT_OFFSET && field!=TYPE && field!=CODE)) 
				return 0;
			break;
		case HTTP:
			if(field<PAYLOAD || (field>TCP_OPTIONS && (field<=BASE_HTTP_DEFS || field>=END_HTTP_DEFS)))
				return 0;
			break;
		case FTP:
			if(field<PAYLOAD || (field>TCP_OPTIONS && (field<=BASE_FTP_DEFS || field>=END_FTP_DEFS)))
				return 0;
			break;
		default:
			return 0;
	}
	
	return 1;
}

struct unmarshal_data {
	int hash_algorithm;
	int padding_behavior;
	int distribution_type;
	int median;
	int standard_deviation;
	int seed;
	int pattern_type;
	char *pattern;
	char *regexp;
	int num_of_matches;
	char **replaceVector;
};

int unmarshalBuffer(int function,char *buffer,struct unmarshal_data *data); 

int unmarshalBuffer(int function,char *buffer,struct unmarshal_data *data) {
	int hash_algorithm=0;
	int padding_behavior=0;
	int median=0;
	int standard_deviation=0;
	int distribution_type=0;
	int seed=0,pattern_type=0;
	char pattern[1024];
	char *pos;
	char *regexp=NULL,*tmpbuf;
	int num_of_matches = 0,i = 0;
	char **replaceVector=NULL;
		
	if(buffer==NULL) 
		return 0;

	switch(function) {
		case UNCHANGED:
		case MAP:
		case ZERO:
		case PREFIX_PRESERVING:
		case PREFIX_PRESERVING_MAP:
		case RANDOM:
		case FILENAME_RANDOM:
		case CHECKSUM_ADJUST:
			return 1;
		case STRIP:
			sscanf(buffer,"%d",&seed);
			break;
		case HASHED:
		{
			char *tmp = buffer;
			if(buffer[0]=='\0') 
				return 0;
			if((pos=strchr(buffer,','))==NULL || *(pos+1)=='\0')
				return 0;

			*pos = '\0';

			hash_algorithm = str2anonid(tmp);
			*pos = ',';

			tmp = pos + 1;

			padding_behavior=str2anonid(tmp);
			
			if(hash_algorithm<ANON_SHA || hash_algorithm>ANON_DES)
				return 0;
			if(padding_behavior!=PAD_WITH_ZERO && padding_behavior!=STRIP_REST && padding_behavior!=UNCHANGED) 
				return 0;
			break;
		}
		case MAP_DISTRIBUTION:
		{
			char *tmp_ptr = buffer;
			if(buffer[0]=='\0') 
				return 0;
			if((pos=strchr(tmp_ptr,','))==NULL)// || *(pos+1)=='\0')
				return 0;
			*pos = '\0';
			
			distribution_type=str2anonid(tmp_ptr);
			if(distribution_type!=UNIFORM && distribution_type!=GAUSSIAN)
				return 0;
			tmp_ptr = pos + 1;
			*pos = ',';

			if((pos = strchr(tmp_ptr, ',')) == NULL)
				return(0);
			*pos = '\0';
			median = atoi(tmp_ptr);
			*pos = ',';

			tmp_ptr = pos + 1;

			standard_deviation = atoi(tmp_ptr);

			break;
		}
		case PATTERN_FILL:
		{
			char *tmp = buffer;
			if(buffer[0]=='\0') 
				return 0;
			if((pos=strchr(buffer,','))==NULL || *(pos+1)=='\0')
				return 0;

			*pos = '\0';
			pattern_type=str2anonid(tmp);
			*pos = ',';

			tmp = pos + 1;

			memcpy(pattern, tmp, strlen(tmp)+1);

			if(pattern_type!=0 && pattern_type!=1)
				return 0;
			break;
		}
		case REPLACE:
			if(buffer[0]=='\0') 
				return 0;
			sscanf(buffer,"%s",pattern);
			break;
		case REGEXP:
			if(buffer[0]=='\0') 
				return 0;
				
			tmpbuf=(char *)strdup(buffer);
			pos=strchr(tmpbuf,',');
			if(pos==NULL) {
				return 0;
			}
			*pos='\0';
			regexp=(char *)strdup(tmpbuf);
			tmpbuf=pos+1;
			
			pos=strchr(tmpbuf,',');
			if(pos==NULL) {
				return 0;
			}
			*pos='\0';
			num_of_matches=atoi(tmpbuf);	
			tmpbuf=pos+1;
			DEBUG_CMD(Debug_Message(">>>>>>> REGEXP: %s %d", regexp, num_of_matches));
			replaceVector=(char **)malloc(num_of_matches*sizeof(char *));
			memset(replaceVector,0,num_of_matches*sizeof(char *));	
			for(i=0;i<(num_of_matches-1);i++) {
				pos=strchr(tmpbuf,',');
				if(pos==NULL) {
					DEBUG_CMD(Debug_Message("pos is NULL !"));
					return 0;
				}
				*pos='\0';
				DEBUG_CMD(Debug_Message("REPLACE VECTOR[%d]=%s", i, tmpbuf));
				if(strcmp(tmpbuf,"NULL")!=0) 
					replaceVector[i]=(char *)strdup(tmpbuf);
				tmpbuf=pos+1;
			}
			
			DEBUG_CMD(Debug_Message("REPLACE VECTOR[%d]=%s", i, tmpbuf));
			if(strcmp(tmpbuf,"NULL")!=0) 
				replaceVector[i]=(char *)strdup(tmpbuf);
			
			break;
		default:
			DEBUG_CMD(Debug_Message("UNKNOWN FUNCTION"));
			return 0;
			
	}
	
	if(data) {
		data->seed=seed;
		data->hash_algorithm=hash_algorithm;
		data->padding_behavior=padding_behavior;
		data->distribution_type=distribution_type;
		data->median=median;
		data->standard_deviation=standard_deviation;
		data->pattern_type=pattern_type;
		if(function==PATTERN_FILL || function==REPLACE) {
			data->pattern=strdup(pattern);
		}
		else {
			data->pattern=NULL;
		}
		data->regexp=regexp;
		data->num_of_matches=num_of_matches;
		data->replaceVector=replaceVector;
	}

	return 1;
}

int can_field_be_applied_to_function(int anonymization_function,int field) {
	if((anonymization_function==PREFIX_PRESERVING || anonymization_function==PREFIX_PRESERVING_MAP) && field!=SRC_IP && field!=DST_IP) {
		DEBUG_CMD(Debug_Message("PREFIX_PRESERVING can only be applied to IP addresses"));
		return 0;
	}

	if((anonymization_function==MAP ||anonymization_function==MAP_DISTRIBUTION) && (field<CHECKSUM || field>CODE || field==OPTIONS || field==TCP_OPTIONS)) {
		DEBUG_CMD(Debug_Message("MAP/MAP_DISTRIBUTION can only be applied to IP,TCP,UDP and ICMP headers (except IP and TCP options)"));
		return 0;
	}
	
	if(anonymization_function==STRIP && (field!=PAYLOAD) && (field!=OPTIONS) && (field!=TCP_OPTIONS) && ((field<=BASE_HTTP_DEFS)
		|| (field>=END_HTTP_DEFS)) && ((field<=BASE_FTP_DEFS) || (field>=END_FTP_DEFS))) {
		DEBUG_CMD(Debug_Message("STRIP can only be applied to IP and TCP options, PAYLOAD and all HTTP, FTP headers"));
		return 0;
	}

	/*if(anonymization_function==HASHED && (field>=CHECKSUM &&  field<=CODE)) {
		printf("HASHING cannot be performed on headers\n");
		return 0;
	}*/
	
	if(anonymization_function==REPLACE && (field>=CHECKSUM &&  field<=CODE)) {
		DEBUG_CMD(Debug_Message("REPLACE cannot be performed on headers"));
		return 0;
	}
	
	if(anonymization_function==CHECKSUM_ADJUST && field!=CHECKSUM) {
		DEBUG_CMD(Debug_Message("CHECKSUM_ADJUST can only be applied to CHECKSUM field"));
		return 0;
	}

	if(field == FIELD_VERSION || field == IHL)
	{
		DEBUG_CMD(Debug_Message("Anonymization of IP fields Version & Internet Header Length is not supported to maintain usability of anonymized data."));
		return(0);
	}

	return 1;

}


static int anonymize_instance(mapidflib_function_instance_t *instance,
				 MAPI_UNUSED int fd,
				 MAPI_UNUSED mapidflib_flow_mod_t *flow_mod)
{
	mapiFunctArg* args=instance->args;
	int protocol = 0, field_description = 0, anonymization_function = 0 ;
	char *marshalledBuffer = NULL,*ptr=NULL;
	struct anonymize_data *data = NULL;
	
	marshalledBuffer=getargstr(&args);
	
	/***** protocol *****/
	ptr=strchr(marshalledBuffer,',');
	if(ptr==NULL) {
		return MFUNCT_INVALID_ARGUMENT_1;
	}
	*ptr='\0';
	
	if((protocol=str2anonid(marshalledBuffer))==-1) 
		return MFUNCT_INVALID_ARGUMENT_1;
	
	/************ field *********/
	marshalledBuffer=ptr+1;
	ptr=strchr(marshalledBuffer,',');
	if(ptr==NULL) {
		return MFUNCT_INVALID_ARGUMENT_2;
	}
	*ptr='\0';
	
	if((field_description=str2anonid(marshalledBuffer))==-1) 
		return MFUNCT_INVALID_ARGUMENT_2;
	
	/********** function ******/
	marshalledBuffer=ptr+1;
	ptr=strchr(marshalledBuffer,',');
	if(ptr!=NULL) {
		*ptr='\0';
		if((anonymization_function=str2anonid(marshalledBuffer))==-1) 
			return MFUNCT_INVALID_ARGUMENT_3;
		marshalledBuffer=ptr+1;
	}
	else {
		if((anonymization_function=str2anonid(marshalledBuffer))==-1) 
			return MFUNCT_INVALID_ARGUMENT_3;
		marshalledBuffer=NULL;
	}
	
	//printf("PROTOCOL: %d FIELD_DESCRIPTION: %d FUNCTION: %d\n",protocol,field_description,anonymization_function);
	//printf("MARSHALLED PARAMETERS: %s\n",marshalledBuffer);
	
	//first trivial sanity checks
	if(protocol<IP || protocol>FTP) {
		return MFUNCT_INVALID_ARGUMENT_1;
	}

	//field shouldn't be special enumeration like BASE_FTP_DEFS
	if(((field_description<=BASE_FIELD_DEFS || field_description>=END_FIELD_DEFS)
	        && field_description!=FLOW)
		|| field_description==BASE_FTP_DEFS 
		|| field_description==END_FTP_DEFS 
		|| field_description==BASE_HTTP_DEFS
		|| field_description==END_HTTP_DEFS) {
		
		return MFUNCT_INVALID_ARGUMENT_2;
	}

	if(anonymization_function<UNCHANGED || anonymization_function>REGEXP) {
		DEBUG_CMD(Debug_Message("UNKNOWN FUNCTION"));
		return MFUNCT_INVALID_ARGUMENT_3;
	}

	if(!can_field_be_applied_to_protocol(protocol,field_description)) {
		DEBUG_CMD(Debug_Message("FIELD CANNOT BE APPLIED TO SPECIFIC PROTOCOL"));
		return MFUNCT_INVALID_ARGUMENT_2;
	}

	if(!can_field_be_applied_to_function(anonymization_function,field_description)) {
		DEBUG_CMD(Debug_Message("FIELD CANNOT BE APPLIED TO SPECIFIC FUNCTION"));
		return MFUNCT_INVALID_ARGUMENT_2;
	}

	if(marshalledBuffer!=NULL && unmarshalBuffer(anonymization_function,marshalledBuffer,NULL)==0) {
		DEBUG_CMD(Debug_Message("UNMARSHALLING FAILED"));
		return MFUNCT_INVALID_ARGUMENT_4;
	}
	
	data=(struct anonymize_data *)malloc(sizeof(struct anonymize_data));
	data->protocol=protocol;
	data->field=field_description;
	data->function=anonymization_function;
	data->decoded_packet = NULL;

	if(marshalledBuffer)
		data->marshalledBuffer=strdup(marshalledBuffer);
	else 
		data->marshalledBuffer=NULL;

	data->fd = fd;
	instance->internal_data=(void *)data;

  	return 0;
};

///////////////////////////////
int various_inited=0;

void init_mapping_tables() {
	memset(ipMappingTable,0,MAPPING_ENTRIES*sizeof(mapNode *));
	memset(portsMappingTable,0,MAPPING_ENTRIES*sizeof(mapNode *));
	memset(generalMapping32Table,0,MAPPING_ENTRIES*sizeof(mapNode *));
	memset(generalMapping16Table,0,MAPPING_ENTRIES*sizeof(mapNode *));
	memset(generalMapping8Table,0,MAPPING_ENTRIES*sizeof(mapNode *));
}



static int anonymize_init(mapidflib_function_instance_t *instance, MAPI_UNUSED int fd)
{
	int protocol, field_description, anonymization_function;
	char *marshalledBuffer;
	
	//mapiFunctArg* args=instance->args;
	struct anonymize_data *data;
	struct unmarshal_data *unmarshaled;

	extern nodehdr_t addr_propagate;

	data=(struct anonymize_data *)(instance->internal_data);
	protocol=data->protocol;
	field_description=data->field;
	anonymization_function=data->function;
	marshalledBuffer=data->marshalledBuffer;

	data->first_anon_instance = fhlp_get_function_instance_byname(instance->hwinfo->gflist, fd, "ANONYMIZE");

	switch(anonymization_function) {
		case UNCHANGED:
		case MAP:
		case ZERO:
		case PREFIX_PRESERVING:
		case PREFIX_PRESERVING_MAP:
		case RANDOM:
		case FILENAME_RANDOM:
		case CHECKSUM_ADJUST:
			break;
		default: 
			unmarshaled=(struct unmarshal_data *)malloc(sizeof(struct unmarshal_data));
			if(unmarshalBuffer(anonymization_function,marshalledBuffer,unmarshaled)==0) {
				DEBUG_CMD(Debug_Message("UNMARSHALLING FAILED"));
				return -1;
			}

			data->seed=unmarshaled->seed;
			data->hash_algorithm=unmarshaled->hash_algorithm;
			data->padding_behavior=unmarshaled->padding_behavior;
			data->median=unmarshaled->median;
			data->standard_deviation=unmarshaled->standard_deviation;
			data->pattern_type=unmarshaled->pattern_type;
			data->distribution_type=unmarshaled->distribution_type;
			if(unmarshaled->pattern)
				data->pattern=strdup(unmarshaled->pattern);
			else
				data->pattern=NULL;
			
			data->regexp=unmarshaled->regexp;
			data->num_of_matches=unmarshaled->num_of_matches;
			data->replaceVector=unmarshaled->replaceVector;

			free(unmarshaled);
	}

	if(!various_inited) {
		init_mapping_tables();
		gen_table();
		srand48((long)time(NULL));
		lookup_init(&addr_propagate);
		various_inited=1;
	}


	
  	return 0;
}

void swap(unsigned char *a,unsigned char *b) {
	unsigned char c;
	c=*a;
	*a=*b;
	*b=c;
}

void checkSwap(unsigned char *field_pointer,int field) {
	if(field==SRC_IP || field==DST_IP || field==SEQUENCE_NUMBER || field==ACK_NUMBER) {
		swap(&field_pointer[0],&field_pointer[3]);
		swap(&field_pointer[1],&field_pointer[1]);
	}
	else if(field==SRC_PORT || field==DST_PORT || field==PACKET_LENGTH) {
		swap(&field_pointer[0],&field_pointer[1]);
	}
}

////////////////////////////////
struct httpheader default_http_header;
void apply_function_to_field(int function,int protocol,int field,unsigned char *field_pointer,int len,unsigned char *header_pointer,int header_len,mapipacket *packet,struct anonymize_data *params);

void anonymize_field(int protocol, int field, int function,mapipacket *packet,struct anonymize_data *params) 
{
	unsigned char *field_pointer=NULL;
	unsigned char *header_pointer=NULL;
	unsigned short len=0,header_len=0;
	int i;
	
	if(!packet) {
		DEBUG_CMD(Debug_Message("WARNING: NULL packet"));
		return;
	}

	if(function==UNCHANGED) 
		return;
	
	switch(protocol) {
		case IP:
			if (packet->iph) {
				switch(field) {
				case PAYLOAD:
					field_pointer=(unsigned char *)(packet->iph)+sizeof(IPHdr)+packet->ip_options_len;
					header_pointer=field_pointer;
					len=header_len=ntohs(packet->iph->ip_len)-sizeof(IPHdr)-packet->ip_options_len;
					break;
				case CHECKSUM:
					field_pointer=(unsigned char *)(&(packet->iph->ip_csum));
					len=2;
					break;
				case TTL:
					field_pointer=(unsigned char *)(&(packet->iph->ip_ttl));
					len=1;
					break;
				case SRC_IP:
					field_pointer=(unsigned char *)(&(packet->iph->ip_src));
					len=4;
					break;
				case DST_IP:
					field_pointer=(unsigned char *)(&(packet->iph->ip_dst));
					len=4;
					break;
				case TOS:
					field_pointer=(unsigned char *)(&(packet->iph->ip_tos));
					len=1;
					break;
				case ID:
					field_pointer=(unsigned char *)(&(packet->iph->ip_id));
					len=2;
					break;
				case FRAGMENT_OFFSET:
					field_pointer=(unsigned char *)(&(packet->iph->ip_off));
					len=2;
					break;
				case FIELD_VERSION:
					field_pointer=(unsigned char *)(&(packet->iph->ip_verhl));
					len=1;
					break;
				case IHL:
					field_pointer=(unsigned char *)(&(packet->iph->ip_verhl));
					len=1;
					break;
				case PACKET_LENGTH:
					field_pointer=(unsigned char *)(&(packet->iph->ip_len));
					len=2;
					break;
				case IP_PROTO:
					field_pointer=(unsigned char *)(&(packet->iph->ip_proto));
					len=1;
					break;
				case OPTIONS: 
					field_pointer=(unsigned char *)(packet->ip_options_data);
					header_pointer=(unsigned char *)(packet->ip_options_data);
					len=header_len=packet->ip_options_len;
					break;
				default:
					break;
				}
			} else if (packet->ip6h) {
				switch(field) {
				case PAYLOAD:
					field_pointer = packet->ipdata;
					header_pointer = field_pointer;
					len = header_len = packet->ipdsize;
					break;
				case TOS: { /* Traffic Class */
					/* not on byte boundary, so need to copy value into
					 * our own variable, and copy result back again */
					unsigned char ttl;
					unsigned char *flow = (unsigned char *)&packet->ip6h->ip6_flow;
					ttl = (flow[0] << 4) + (flow[1] >> 4);
					apply_function_to_field(function, protocol, field,
								&ttl, 1, header_pointer,
								header_len, packet, params);	
					flow[0] = (flow[0] & 0xf0) | (ttl >> 4);
					flow[1] = (flow[1] & 0xf) | (ttl << 4);
					return;
				}
				case FLOW: { /* Flow Label */
					/* not on byte boundary, so need to copy value into
					 * our own variable, and copy result back again
					 * last 20 bits are the flow label */
					unsigned int flow = ntohl(packet->ip6h->ip6_flow) & 0xfffff;
					apply_function_to_field(function, protocol, field,
								(unsigned char *)&flow, 4,
								header_pointer, header_len,
								packet, params);
					/* hopefully ok to ignore top 12 bits of anon result */
					packet->ip6h->ip6_flow = htonl((packet->ip6h->ip6_flow & 0xfff00000) | (flow & 0xfffff));
					return;
				}
				case PACKET_LENGTH: /* Really the Payload Length */
					field_pointer = (unsigned char *)&packet->ip6h->ip6_plen;
					len=2;
					break;
				case IP_PROTO: /* Really the Next Header field */
					field_pointer = (unsigned char *)&packet->ip6h->ip6_nxt;
					len = 1;
					break;
				case TTL: /* Hop Limit */
					field_pointer = (unsigned char *)&packet->ip6h->ip6_hlim;
					len = 1;
					break;
				case SRC_IP:
					field_pointer = (unsigned char *)&packet->ip6h->ip6_src;
					len = 16;
					break;
				case DST_IP:
					field_pointer = (unsigned char *)&packet->ip6h->ip6_dst;
					len = 16;
					break;
				default:
					break;
				}

			} else
				return;
			break;
		case TCP:
			if(!packet->tcph) 
				return;
			
			if(field>=SRC_IP && field<=FRAGMENT_OFFSET) { //hierarchical	
				return anonymize_field(IP,field,function,packet,params);
				break;
			}
			switch(field) {
				case PAYLOAD:
					field_pointer=(unsigned char *)(packet->data);
					header_pointer=(unsigned char *)(packet->data);
					len=header_len=packet->dsize;
					break;
				case CHECKSUM:
					field_pointer=(unsigned char *)(&(packet->tcph->th_sum));
					len=2;
					break;
				case SRC_PORT:
					field_pointer=(unsigned char *)(&(packet->tcph->th_sport));
					len=2;
					break;
				case DST_PORT:
					field_pointer=(unsigned char *)(&(packet->tcph->th_dport));
					len=2;
					break;
				case SEQUENCE_NUMBER:
					field_pointer=(unsigned char *)(&(packet->tcph->th_seq));
					len=4;
					break;
				case ACK_NUMBER:
					field_pointer=(unsigned char *)(&(packet->tcph->th_ack));
					len=4;
					break;
				case WINDOW:
					field_pointer=(unsigned char *)(&(packet->tcph->th_win));
					len=2;
					break;
				case FLAGS:	
					field_pointer=(unsigned char *)(&(packet->tcph->th_flags));
					len=1;
					break;
				case OFFSET_AND_RESERVED:
					field_pointer=(unsigned char *)(&(packet->tcph->th_offx2));
					len=1;
					break;
				case URGENT_POINTER: 
					field_pointer=(unsigned char *)(&(packet->tcph->th_urp));
					len=2;
					break;
				case TCP_OPTIONS:
					field_pointer=packet->tcp_options_data;
					header_pointer=packet->tcp_options_data;
					len=packet->tcp_options_len;
					break;
				default:
					break;
			}
			break;
		case UDP: 
			if(!packet->udph) 
				return;
			
			if(field>=SRC_IP && field<=FRAGMENT_OFFSET) { //hierarchical	
				return anonymize_field(IP,field,function,packet,params);
				break;
			}
			switch(field) {
				case PAYLOAD:
					field_pointer=(unsigned char *)(packet->udph)+sizeof(UDPHdr); //maybe packet->data should be better
					header_pointer=field_pointer;
					len=header_len=packet->dsize;
					break;
				case CHECKSUM:
					field_pointer=(unsigned char *)(&(packet->udph->uh_chk));
					len=2;
					break;
				case SRC_PORT:
					field_pointer=(unsigned char *)(&(packet->udph->uh_sport));
					len=2;
					break;
				case DST_PORT:
					field_pointer=(unsigned char *)(&(packet->udph->uh_dport));
					len=2;
					break;
				case UDP_DATAGRAM_LENGTH:
					field_pointer=(unsigned char *)(&(packet->udph->uh_len));
					len=2;
					break;
				default:
					break;
			}
			break;
		case ICMP:
		        if (packet->icmp6h) {
			    switch(field) {
			    case CHECKSUM:
				field_pointer=(unsigned char *)(&(packet->icmp6h->icmp6_cksum));
				len=2;
				break;
			    }
			    break;
			}

			if(!packet->icmph) 
				return;

			if(field>=SRC_IP && field<=FRAGMENT_OFFSET) { //hierarchical	
				return anonymize_field(IP,field,function,packet,params);
				break;
			}
			switch(field) {
				case PAYLOAD:
					field_pointer=(unsigned char *)(packet->icmph)+sizeof(ICMPHdr);
					header_pointer=field_pointer;
					len=header_len=packet->dsize;
					break;
				case CHECKSUM:
					field_pointer=(unsigned char *)(&(packet->icmph->csum));
					len=2;
					break;
				case TYPE:
					field_pointer=(unsigned char *)(&(packet->icmph->type));
					len=1;
					break;
				case CODE:
					field_pointer=(unsigned char *)(&(packet->icmph->code));
					len=1;
					break;
				default:
					break;
			}
			break;
		case HTTP:
			{
			struct httpheader *h;
			//decode the http if we haven't done so
			if(packet->num_of_upper_layer_protocols==0) {
				packet->upper_layer_protocol_headers[0]=&default_http_header;
				if(http_decode(packet,(struct httpheader *)packet->upper_layer_protocol_headers[0])==-1) {
					return;
				}
				else {
					packet->upper_layer_names[0]=HTTP;
					packet->num_of_upper_layer_protocols++;
					h=(struct httpheader *)packet->upper_layer_protocol_headers[0];
				}
			}
			else { //try to find the HTTP header
				int j;
				for(j=0;j<packet->num_of_upper_layer_protocols;j++) {
					if(packet->upper_layer_names[j]==HTTP)
						break;
				}

				if(j==packet->num_of_upper_layer_protocols) 
					return;
				h=(struct httpheader *)packet->upper_layer_protocol_headers[j];
				
			}

			if(field>=SRC_IP && field<=FRAGMENT_OFFSET) { //hierarchical	
				anonymize_field(IP,field,function,packet,params);
				return;
				break;
			}
			
			if(field>=SRC_PORT && field<=TCP_OPTIONS) {
				anonymize_field(TCP,field,function,packet,params);
				return;
				break;
			}
			
			for(i=0;i<h->pipeline_depth;i++) {
				switch(field) {
					case PAYLOAD:
						field_pointer=h->pointers_to_value[i][HTTP_PAYLOAD-BASE_HTTP_DEFS-1];
						header_pointer=h->pointers_to_value[i][HTTP_PAYLOAD-BASE_HTTP_DEFS-1];
						len=header_len=h->value_length[i][HTTP_PAYLOAD-BASE_HTTP_DEFS-1];
						break;
					default:
						field_pointer=h->pointers_to_value[i][field-BASE_HTTP_DEFS-1];
						len=h->value_length[i][field-BASE_HTTP_DEFS-1];
					
						header_pointer=h->pointers_to_header[i][field-BASE_HTTP_DEFS-1];
						header_len=h->header_length[i][field-BASE_HTTP_DEFS-1];
						break;
				}
				apply_function_to_field(function,protocol,field,field_pointer,len,header_pointer,header_len,packet,params);
			}
			return;
			break;	
			}
		case FTP:
			{
			struct ftpheader *h;
			//decode the http if we haven't done so
			if(packet->num_of_upper_layer_protocols==0) {
				packet->upper_layer_protocol_headers[0]=(void *)malloc(sizeof(struct ftpheader));
				if(ftp_decode(packet,(struct ftpheader *)packet->upper_layer_protocol_headers[0])==-1) {
					//printf("Cannot parse FTP protocol\n");
					free(packet->upper_layer_protocol_headers[0]);
					return;
				}
				else {
					packet->upper_layer_names[0]=FTP;
					packet->num_of_upper_layer_protocols++;
					h=(struct ftpheader *)packet->upper_layer_protocol_headers[0];
				}
			}
			else { //try to find the HTTP header
				int j;
				for(j=0;j<packet->num_of_upper_layer_protocols;j++) {
					if(packet->upper_layer_names[j]==FTP)
						break;
				}

				if(j==packet->num_of_upper_layer_protocols) 
					return;
				h=(struct ftpheader *)packet->upper_layer_protocol_headers[j];
				
			}

			if(field>=SRC_IP && field<=FRAGMENT_OFFSET) { //hierarchical	
				return anonymize_field(IP,field,function,packet,params);
				break;
			}
			
			if(field>=SRC_PORT && field<=TCP_OPTIONS) {
				return anonymize_field(TCP,field,function,packet,params);
				break;
			}

			switch(field) {
				case PAYLOAD:
					return;
				default:
					field_pointer=h->pointers_to_value[field-BASE_FTP_DEFS-1];
					len=h->value_length[field-BASE_HTTP_DEFS-1];
					
					header_pointer=h->pointers_to_header[field-BASE_FTP_DEFS-1];
					header_len=h->header_length[field-BASE_FTP_DEFS-1];
					break;
			}
			break;	
			}
		default:
		
			break;
	}
	

	apply_function_to_field(function,protocol,field,field_pointer,len,header_pointer,header_len,packet,params);	
}

void apply_function_to_field(int function,int protocol,int field,unsigned char *field_pointer,int len,
	unsigned char *header_pointer,int header_len,mapipacket *packet,struct anonymize_data *params) {
	mapNode **mapTable;
	int *counter;
	unsigned char *packet_end;
	unsigned int total_len;
	unsigned char DES3_keys[24] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23 } ;
	unsigned char AES_keys[32] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x01, 0x23, 0x45, 0x67, 0x23, 0x45, 0x67, 0x89};
	int helper;
	
	if(!field_pointer && function != CHECKSUM_ADJUST) //a HTTP reply for example doesn't have URI
		return;
	
	switch(function) {
		case MAP:
			if(field==SRC_IP || field==DST_IP) {
				mapTable=ipMappingTable;
				counter=&ip_count;
			}
			else if(field==SRC_PORT || field==DST_PORT) {
				mapTable=portsMappingTable;
				counter=&ports_count;
			}
			else {
				if(len==4) {
					mapTable=generalMapping32Table;
					counter=&general32_count;
				}
				else if(len==2) {
					mapTable=generalMapping16Table;
					counter=&general16_count;
				}
				else {
					mapTable=generalMapping8Table;
					counter=&general8_count;
				}
			}
			map_field(field_pointer,len,mapTable,counter);
			//checkSwap(field_pointer,field);	
						
			break;
		case MAP_DISTRIBUTION:
			map_distribution(field_pointer,len,params->distribution_type,params->median,params->standard_deviation);
			//checkSwap(field_pointer,field);	
			break;
		case PREFIX_PRESERVING:
			prefix_preserving_anonymize_field(field_pointer, len);
			break;
		case PREFIX_PRESERVING_MAP:
			hide_addr(field_pointer);
			break;
		case STRIP:
			//printf("++I will call STRIP and I will keep %d bytes\n",params->seed);
			if (packet->iph) {
				total_len = ntohs(packet->iph->ip_len);
				packet_end = (unsigned char *)packet->iph + total_len;
			} else { /* assume IPv6 when not IPv4 */
				total_len = ntohs(packet->ip6h->ip6_plen) + IP6_HEADER_LEN;
				packet_end = (unsigned char *)packet->ip6h + total_len;
			}
			strip(packet,header_pointer,header_len,params->seed,total_len,packet_end);
			break;
		case HASHED:
			//printf("I will call HASH for algorithm %d and padding %d\n",params->hash_algorithm,params->padding_behavior);
			if (packet->iph) {
				total_len = ntohs(packet->iph->ip_len);
				packet_end = (unsigned char *)packet->iph + total_len;
			} else { /* assume IPv6 when not IPv4 */
				total_len = ntohs(packet->ip6h->ip6_plen) + IP6_HEADER_LEN;
				packet_end = (unsigned char *)packet->ip6h + total_len;
			}
			int donotreplace=0;
			if(field>=CHECKSUM &&  field<=CODE)
				donotreplace=1;
			switch(params->hash_algorithm) {
				case ANON_SHA:
					sha1_hash(field_pointer,len,params->padding_behavior,packet,total_len,packet_end,donotreplace);
					break;
				case ANON_MD5:
					md5_hash(field_pointer,len,params->padding_behavior,packet,total_len,packet_end,donotreplace);
					break;
				case ANON_CRC32:
					crc32_hash(field_pointer,len,params->padding_behavior,packet,total_len,packet_end,donotreplace);
					break;
				case ANON_SHA_2:
					sha256_hash(field_pointer,len,params->padding_behavior,packet,total_len,packet_end,donotreplace);
					break;
				case ANON_DES:
				case ANON_TRIPLEDES:
					des_hash(field_pointer,len,(unsigned char *)DES3_keys,params->padding_behavior,packet);
					break;
				case ANON_AES:
					aes_hash(field_pointer,len,(unsigned char *)AES_keys,params->padding_behavior,packet);
					break;
				default:
					DEBUG_CMD(Debug_Message("Fatal Error!"));
					exit(0);
			}
			break;
		case PATTERN_FILL:
			//printf("I will call PATTERN_FILL with type %d and pattern: %s\n",params->pattern_type,params->pattern);
			switch(params->pattern_type) {
				case 0: //integers
					helper=atoi(params->pattern);
					pattern_fill_field(field_pointer,len,params->pattern_type,(void *)&helper);
					break;
				case 1:
					pattern_fill_field(field_pointer,len,params->pattern_type,(void *)params->pattern);
					break;
			}
			checkSwap(field_pointer,field);	
			break;
		case FILENAME_RANDOM:
			//printf("++I will call FILENAME_RANDOM (%p,%d)\n",field_pointer,len);
			filename_random_field(field_pointer,len);
			break;
		case RANDOM:
			//printf("++I will call RANDOM %u.%u.%u.%u\n",field_pointer[0],field_pointer[1],field_pointer[2],field_pointer[3]);
			random_field(field_pointer,len);	
			break;
		case ZERO:
			memset(field_pointer,0,len);
			break;
		case REPLACE:
			//printf("++I will call REPLACE with pattern: %s\n",params->pattern);
			if (packet->iph) {
				total_len = ntohs(packet->iph->ip_len);
				packet_end = (unsigned char *)packet->iph + total_len;
			} else { /* assume IPv6 when not IPv4 */
				total_len = ntohs(packet->ip6h->ip6_plen) + IP6_HEADER_LEN;
				packet_end = (unsigned char *)packet->ip6h + total_len;
			}
			replace_field(field_pointer,len,(unsigned char *)params->pattern,strlen(params->pattern),packet,total_len,packet_end);
			break;
		case CHECKSUM_ADJUST:
			switch(protocol) {
				case IP:
					if (packet->iph)
						packet->iph->ip_csum=calculate_ip_sum(packet);
					if(packet->tcph) { //pseudoheader uses some info from IP
						packet->tcph->th_sum=calculate_tcp_sum(packet);
					}
					else if(packet->udph) {
						packet->udph->uh_chk=calculate_udp_sum(packet);
					}
					else if(packet->icmp6h) {
						//icmpv6 checksum uses pseudoheader with IP info
						packet->icmp6h->icmp6_cksum=calculate_icmp_sum(packet);
					}
					break;
				case TCP:
					packet->tcph->th_sum=calculate_tcp_sum(packet);
					break;
				case UDP:
					packet->udph->uh_chk=calculate_udp_sum(packet);
					break;
				case ICMP:
					if (packet->icmph) {
						packet->icmph->csum=calculate_icmp_sum(packet);
					}
					else if(packet->icmp6h) {
						packet->icmp6h->icmp6_cksum=calculate_icmp_sum(packet);
					}
					break;
				case HTTP:
				case FTP:
					if(packet->tcph) { //pseudoheader uses some info from IP
						packet->tcph->th_sum=calculate_tcp_sum(packet);
					}
					break;
			}
			break;
		case REGEXP:
			if (packet->iph) {
				total_len = ntohs(packet->iph->ip_len);
				packet_end = (unsigned char *)packet->iph + total_len;
			} else { /* assume IPv6 when not IPv4 */
				total_len = ntohs(packet->ip6h->ip6_plen) + IP6_HEADER_LEN;
				packet_end = (unsigned char *)packet->ip6h + total_len;
			}
			reg_exp_substitute(field_pointer,len,params->regexp,params->replaceVector,params->num_of_matches,packet,total_len,packet_end);
			break;
		default:
			break;
	}
}

mapid_pkthdr_t *last_header_seen=NULL;
mapipacket decoded_packet;

int anonymize_stream(mapidflib_function_instance_t *instance,struct cooking_data *flow,struct anonymize_data *params,mapid_pkthdr_t* pkt_head, unsigned char *mod_pkt) {
	struct pcap_pkthdr pkthdr;
	mapid_pkthdr_t* mapi_head = NULL;
	
	mapi_head=pkt_head;
		
	pkthdr.caplen=mapi_head->caplen;
	pkthdr.len=mapi_head->wlen;
	pkthdr.ts.tv_sec=mapi_head->ts; //XXX
	pkthdr.ts.tv_usec=mapi_head->ts;

	flow->decoded_packet=&decoded_packet;
	decode_packet(instance->hwinfo->link_type,instance->hwinfo->cap_length,&pkthdr,mod_pkt,flow->decoded_packet);	
	((mapipacket *)flow->decoded_packet)->dsize=flow->client_size;
	if(((mapipacket *)flow->decoded_packet)->data==NULL) { //decoder does not work well above 65536
		((mapipacket *)flow->decoded_packet)->data = ((mapipacket *)flow->decoded_packet)->pkt+(mapi_head->caplen - flow->client_size);
	}
	
	last_header_seen = mapi_head;
	anonymize_field(params->protocol,params->field,params->function,flow->decoded_packet,params);
			

	return 1;
}

static int anonymize_process(mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			unsigned char* link_pkt,
			mapid_pkthdr_t* pkt_head)  
{
	struct anonymize_data *params = NULL;
	struct cooking_data *flow = NULL;
	struct pcap_pkthdr pkthdr;
	mapidflib_function_instance_t *cook_instance = NULL;

	params=(struct anonymize_data *)instance->internal_data;
	
	if((cook_instance=fhlp_get_function_instance_byname(instance->hwinfo->gflist,params->fd, "COOKING")) != NULL) {
		flow=(struct cooking_data*)cook_instance->internal_data;
	}
	
	if(flow != NULL && flow->client_headers!=NULL) { //if this is a cooked packet try to anonymize it
		return anonymize_stream(instance,flow,params,pkt_head, link_pkt);
	}

	pkthdr.caplen=pkt_head->caplen;
	pkthdr.len=pkt_head->wlen;
	pkthdr.ts.tv_sec=pkt_head->ts; //XXX 
	pkthdr.ts.tv_usec=pkt_head->ts; 
	
	last_header_seen = pkt_head;

/*	if(flow != NULL && flow->decoded_packet==NULL) {
		flow->decoded_packet=&decoded_packet;
		decode_packet(instance->hwinfo->link_type,instance->hwinfo->cap_length,&pkthdr,(unsigned char *)link_pkt,flow->decoded_packet);	
	}
	
	anonymize_field(params->protocol,params->field,params->function,flow->decoded_packet,params);
*/	

	if(params->decoded_packet == NULL) {
		params->decoded_packet=malloc(sizeof(mapipacket));
	}

//	if(params->first_anon_instance == NULL || params->first_anon_instance == instance) {
	// commented out to correct a bug found by Arne -> danton
		decode_packet(instance->hwinfo->link_type,instance->hwinfo->cap_length,&pkthdr,(unsigned char *)link_pkt,params->decoded_packet);
//	}
	
	anonymize_field(params->protocol,params->field,params->function,params->decoded_packet,params);

	return 1;
}

///////////////////////////////////////

static int anonymize_reset(MAPI_UNUSED mapidflib_function_instance_t *instance) 
{
  return 0;
}

//////////////////////////////////////////

static int anonymize_cleanup(MAPI_UNUSED mapidflib_function_instance_t *instance) 
{
  return 0;
}

/////////////////////////////////////////

static mapidflib_function_def_t finfo={
  "", //libname
  "ANONYMIZE", //name
  "Anonymizes packets (header and payload) based on certain rules", //descr
  "s", //argdescr
  MAPI_DEVICE_ALL, //devtype
  MAPIRES_NONE, //Method for returning results
  0, //shm size
  1, //modifies_pkts
  0, //filters packets
  MAPIOPT_AUTO, //Optimization
  anonymize_instance, //instance
  anonymize_init, //init
  anonymize_process, //process
  NULL, //get_result,
  anonymize_reset, //reset
  anonymize_cleanup, //cleanup
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

////////////////////////////////

mapidflib_function_def_t* anonymize_get_funct_info();

//////////////////////////////

mapidflib_function_def_t* anonymize_get_funct_info() {
  return &finfo;
};


