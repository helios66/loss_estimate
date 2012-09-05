#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

#include "anonymization_functions.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "crc32.h"
#include "des.h"
#include "aes.h"

#include <pcre.h>
#include "mapidlib.h"

extern mapid_pkthdr_t *last_header_seen;

extern mapNode *generalMapping32Table[];
extern mapNode *generalMapping16Table[];
extern mapNode *generalMapping8Table[];

/************ REPLACE RANDOM ***********/

void random_field(unsigned char *field, int len)
{
    int i;

    for(i=0;i<len;i++)
    {
	*field = (unsigned char)(rand()%256);
	field++;
    }
}

/********** REPLACE FILENAME (PRINTABLE) ******/

void filename_random_field(unsigned char *p, int len)
{
    unsigned char *pos,*tmp;

    pos=p+len-1;
    while(pos>=p) {
	    if(*pos=='.')
		    break;
	    pos--;
    }

    if(pos<p) //if we can't find a '.'  we randomize the whole field
	    pos=p+len;


    for(tmp=p;tmp<pos;tmp++) {
	    tmp[0]=33+(rand()%(126-33));
    }

}

/********* PATTERN FILL ************/

void pattern_fill_field(unsigned char *field, int len, int pattern_type, void *pattern)
{
    int i;
    
    if(pattern_type == INTEGER) //integer (0-256)
    {
	int int_pattern = *((int *)pattern);
	for(i=0;i<len;i++)
	    field[i] = (unsigned char)int_pattern;
    }
    else if (pattern_type == STR)//string
    {
	int pat_len = strlen(pattern);
	int j=0;
	for(i=0;i<len;i++)
	{
	    field[i]=((char *)pattern)[j];
	    j++;
	    if(j == pat_len) //end of pattern
		j=0;
	}
    }
}

/************** STRIP ************/

void strip (mapipacket *p, unsigned char *field, int len,int keep_bytes, int total_len, unsigned char* packet_end)
{
    if(keep_bytes > len)
		keep_bytes = len;
    //call replace_field to replace field with zero length pattern
    replace_field(field+keep_bytes,len-keep_bytes,(unsigned char *)"", 0,p, total_len, packet_end);
}

/********* DISTRIBUTION / DEVIATION*************/

float box_muller(float m, float s)	/* Implements the Polar form of the Box-Muller
                         		Transformation. (Gaussian)*/
{				        /* mean m, standard deviation s */
	float x1, x2, w, y1;
	static float y2;
	static int use_last = 0;

	if (use_last)		        /* use value from previous call */
	{
		y1 = y2;
		use_last = 0;
	}
	else
	{
		do {
			x1 = 2.0 * drand48() - 1.0;
			x2 = 2.0 * drand48() - 1.0;
			w = x1 * x1 + x2 * x2;
		} while ( w >= 1.0 );

		w = sqrt( (-2.0 * log( w ) ) / w );
		y1 = x1 * w;
		y2 = x2 * w;
		use_last = 1;
	}

	return( m + y1 * s );
}


void map_distribution(unsigned char *field, short len, int distribution_type, int arg1, int arg2)
{
	mapNode **map_table;
	mapValue old_value;
	int mapped_value = 0, distribution_result = 0;

	if(len >= 4)
	{
		map_table = generalMapping32Table;
		old_value.val[0] = *((int *)field);
		old_value.len = 1;
		mapped_value = lookup_value(map_table, &old_value);

		if(!mapped_value)
		{
			int temp_len = (len>=4)?4:len;
    
			if(distribution_type == UNIFORM) //uniform
				distribution_result = (int) (arg2-arg1)*drand48()+arg1; //uniform from arg1 to arg2
			else if (distribution_type == GAUSSIAN) //gaussian
				distribution_result = (int) box_muller(arg1, arg2); //gaussian, mean arg1, deviation arg2

			distribution_result = distribution_result % ((int)pow(256,temp_len));

			*((int *)field) = htonl(distribution_result);
			insert_value(map_table, &old_value, distribution_result);
		}
		else
		{
			*((int *)field) = htonl(mapped_value);
		}

		if(len != 4)
			map_distribution(field+4, len-4, distribution_type, arg1, arg2);
	}
	else if(len == 2)
	{
		map_table = generalMapping16Table;
		old_value.val[0] = *((short *)field);
		old_value.len = 1;
		mapped_value = lookup_value(map_table, &old_value);

		if(!mapped_value)
		{
			if(distribution_type == UNIFORM) //uniform
				distribution_result = (int) (arg2-arg1)*drand48()+arg1; //uniform from arg1 to arg2
			else if (distribution_type == GAUSSIAN) //gaussian
				distribution_result = (int) box_muller(arg1, arg2); //gaussian, mean arg1, deviation arg2

			distribution_result = distribution_result % ((int)pow(256,2));

			*((short *)field) = htons((short)(distribution_result));
			insert_value(map_table, &old_value, distribution_result);
		}
		else
		{
			*((short *)field) = htons((short)(mapped_value));
		}
	}
	else // len == 1
	{
		map_table = generalMapping8Table;
		old_value.val[0] = *field;
		old_value.len = 1;
		mapped_value = lookup_value(map_table, &old_value);

		if(!mapped_value)
		{
			if(distribution_type == UNIFORM) //uniform
				distribution_result = (int) (arg2-arg1)*drand48()+arg1; //uniform from arg1 to arg2
			else if (distribution_type == GAUSSIAN) //gaussian
				distribution_result = (int) box_muller(arg1, arg2); //gaussian, mean arg1, deviation arg2

			distribution_result = distribution_result % ((int)pow(256,1));

			*field = (char)distribution_result;
			insert_value(map_table, &old_value, distribution_result);
		}
		else
		{
			*field = (char) mapped_value;
		}
	}
}

/*********** HASH *********/
void hash_padding(unsigned char *field, int len, int padding_behavior,unsigned char *pattern, int hash_length,mapipacket *p, int total_length, unsigned char * packet_end,int donotreplace)
{
    int i;
	
	if(donotreplace==1) {
		for(i=0;i<len;i++)
			field[i]=pattern[i];
		return;
	}
	
    if(len>=hash_length) //manipulate remaining bytes
    {
		if(padding_behavior == PAD_WITH_ZERO)
		{
			memcpy(field,pattern,hash_length); //copy the hash value
			field+=hash_length;
			for(i=0;i<(len-hash_length);i++)
			{
				*field = '0';
				field++;
			}
		}
		else if(padding_behavior == STRIP_REST) {
			if(hash_length==len) {//no need to strip if sizes are equal 
				memcpy(field,pattern,hash_length); //copy the hash value
				return;
			}
			//replace field with hash value
			replace_field(field,len,pattern,hash_length,p,total_length,packet_end);
		}
    }
    else
    {
	//replace field with hash value
	replace_field(field,len,pattern,hash_length,p,total_length,packet_end);
    }
}

int md5_hash(unsigned char *field, int len, int padding_behavior, mapipacket *p, int total_len, unsigned char * packet_end,int donotreplace)
{ 
    md5_context ctx;
    int hash_length = 16; //fixed
    unsigned char md5sum[16];
	
    if(checkMTU(total_len, len,hash_length))
	return -1;
	
	if(len==0) 
		return 0;

    md5_starts( &ctx );
    md5_update( &ctx, (uint8 *) field, len);
    md5_finish( &ctx, md5sum);

    hash_padding(field, len, padding_behavior,md5sum, hash_length,p, total_len, packet_end,donotreplace);
    return 0;
}

int sha1_hash(unsigned char *field, int len, int padding_behavior, mapipacket *p, int total_len, unsigned char * packet_end,int donotreplace)
{
    sha1_context ctx;
    int hash_length = 20; //fixed
    unsigned char sha1sum[20];
    
    if(checkMTU(total_len, len, hash_length))
	return -1;
	
	if(len==0) 
		return 0;
    
    sha1_starts( &ctx );
    sha1_update( &ctx, (uint8 *) field, len);
    sha1_finish( &ctx, sha1sum);

    hash_padding(field, len, padding_behavior, sha1sum, hash_length,p, total_len, packet_end,donotreplace);
    return 0;
}

int sha256_hash(unsigned char *field, int len, int padding_behavior, mapipacket *p, int total_len, unsigned char * packet_end,int donotreplace)
{
    sha256_context ctx;
    int hash_length = 32; //fixed
    unsigned char sha256sum[32];

    if(checkMTU(total_len, len,hash_length))
	return -1;
	
	if(len==0) 
		return 0;
    
    sha256_starts( &ctx );
    sha256_update( &ctx, (uint8 *) field, len);
    sha256_finish( &ctx, sha256sum);

	hash_padding(field, len, padding_behavior, sha256sum, hash_length,p, total_len, packet_end,donotreplace);
    return 0;
}

int crc32_hash(unsigned char *field, int len, int padding_behavior, mapipacket *p, int total_len, unsigned char * packet_end,int donotreplace)
{
    int hash_length = sizeof(unsigned long);
    unsigned long res;
    
    if(checkMTU(total_len, len,hash_length))
	return -1;
	
	if(len==0) 
		return 0;

    res = get_crc(field,len);
    
    hash_padding(field, len, padding_behavior,(unsigned char *)&res,hash_length, p,total_len, packet_end,donotreplace);
    return 0;
}

int des_hash(unsigned char *field, int len, unsigned char *key, MAPI_UNUSED int padding_behavior, MAPI_UNUSED mapipacket *p)
{
    int hash_length = 8;
    des3_context ctx3;
    unsigned char buf[8] = {0,0,0,0,0,0,0,0};
    int index = 0;
    int rest,i;
    
    des3_set_3keys( &ctx3, key, key+8, key+16 );
    
    while(index<=(len-8))
    {
    	des3_encrypt( &ctx3, field+index, field+index);
    	index +=hash_length;
    }
    rest = len - index;
    if(rest != 0)
    {
	for(i =index; i<len; i++)
	    buf[i-index] = field[index];
    	des3_encrypt( &ctx3, buf, buf);
	for(i =index; i<len; i++)
	    field[i] = buf[i-index];
    }
    //no padding needed
    return 0;
}


int aes_hash(unsigned char *field, int len, unsigned char *key, MAPI_UNUSED int padding_behavior, MAPI_UNUSED mapipacket *p)
{
    int hash_length = 16;
    aes_context ctx;
    unsigned char buf[8] = {0,0,0,0,0,0,0,0};
    int index = 0;
    int rest,i;

    aes_set_key( &ctx, key, 256 );
    
    while(index<=(len-16))
    {
    	aes_encrypt( &ctx, field+index, field+index);
    	index +=hash_length;
    }

    rest = len - index;
    if(rest != 0)
    {
	for(i =index; i<len; i++)
	    buf[i-index] = field[index];
    	aes_encrypt( &ctx, buf, buf);
	for(i =index; i<len; i++)
	    field[i] = buf[i-index];
    }
    //no padding needed
    return 0;
}

/****** MAP FIELD (HASH TABLE)****************/
void map_field(unsigned char *field, short len, mapNode **map_table,int *count)
{
    unsigned int mapped_value;
    mapValue value;

    switch (len) {
    case 1: // 8 bits, len = 1 byte
	value.val[0] = *field;
	value.len = 1; /* 1 * 4 bytes */
	break;
    case 2: // 16 bits, len = 2 bytes
	value.val[0] = *((short *)field);
	value.len = 1; /* 1 * 4 bytes */
	break;
    case 4: // 32 bits, len = 4 bytes
	value.val[0] = *((int *)field);
	value.len = 1; /* 1 * 4 bytes */
	break;
    case 16: // 128 bits, len = 16 bytes
	memcpy(value.val, field, 16);
	value.len = 4; /* 4 * 4 bytes */
	break;
    default:
	return;
    }
    
    mapped_value = lookup_value(map_table, &value);
    
    if(!mapped_value) // NOT FOUND, new mapping
    {
	mapped_value = *count;
	insert_value(map_table, &value, mapped_value);
	(*count)++;
    }

    //put in field the mapped value
    switch (len) {
    case 1: // 8 bits, len = 1 byte
	*field = (char) (mapped_value);
	break;
    case 2: // 16 bits, len = 2 bytes
	*((short *)field) = htons((short) (mapped_value));
	break;
    case 4: // 32 bits, len = 4 bytes
	*((int *)field) = htonl(mapped_value);
	break;
    case 16: // 128 bits, len = 16 bytes
	memset(field, 0, 16);
	((int *)field)[0] = htonl(0x20010db8); /* IPv6 documentation prefix */
	((int *)field)[3] = htonl(mapped_value);
	break;
    }
}

unsigned int lookup_value(mapNode **map_table, mapValue *value)
{
    int hash_pos;
    mapNode * tmp;
    
    if(map_table == NULL) //no hash table
	return 0;

    if (value->len == 1) {
	hash_pos = value->val[0] % MAPPING_ENTRIES;
	for (tmp = map_table[hash_pos]; tmp; tmp = tmp->next)
	    if (tmp->value.len == 1 && tmp->value.val[0] == value->val[0]) //found value
		return tmp->mapped_value;
    } else if (value->len == 4) {
	hash_pos = (value->val[0] ^ value->val[1] ^ value->val[2] ^ value->val[3]) % MAPPING_ENTRIES;
	for (tmp = map_table[hash_pos]; tmp; tmp = tmp->next)
	    if (tmp->value.len == 4 && !memcmp(tmp->value.val, value->val, 16)) //found value
		return tmp->mapped_value;
    }
    return 0;
}

void insert_value(mapNode **map_table, mapValue *value, unsigned int mapped_value)
{
    int hash_pos;
    mapNode *new;

    if (value->len == 1)
	hash_pos = value->val[0] % MAPPING_ENTRIES;
    else if (value->len == 4)
	hash_pos = (value->val[0] ^ value->val[1] ^ value->val[2] ^ value->val[3]) % MAPPING_ENTRIES;
    else return;
    
    new = (mapNode *)malloc(sizeof(mapNode)); //new node
    new->next = map_table[hash_pos];
    new->value = *value;
    new->mapped_value = mapped_value;
    map_table[hash_pos] = new;
}

/************ REPLACE FIELD******************/

int checkMTU(int packet_length, int field_old_length, int field_new_length)
{
    int MTU = 1514;
    
    if(packet_length > MTU) //cooked packet
	return 0;
    
    if((packet_length - field_old_length + field_new_length) > MTU)  //can not replace field, new length > MTU
	return 1;  
    return 0; //OK
}

int replace_field(unsigned char *field, int len,unsigned char * pattern, int pattern_len, mapipacket *p, int total_len, unsigned char *packet_end)
{
    unsigned char * tempData = NULL;
    unsigned char *tempIndex = field+len;
    int i=0,k,j=0;
    int shift = pattern_len - len; //number of bytes added/deleted

    if(pattern_len > 0) //is not strip
    {
	    if(len==pattern_len) {
		    memcpy(field,pattern,pattern_len);
		    return 0;
	    }

	    if(checkMTU(total_len, len,pattern_len))
		return -1;

	    tempData = (unsigned char *)malloc(total_len * sizeof(unsigned char));
	    memcpy(tempData,pattern,pattern_len); //copy pattern to temp buffer
	    
	    while(tempIndex < packet_end) //copy rest of the packet (after replaced field)
	    {
			tempData[pattern_len+i]=*tempIndex;
			tempIndex++;i++;
	    }
	    
	    memcpy(field, tempData, pattern_len+i); //copy temp buffer to packet
	    free(tempData);

	    tempIndex=field + pattern_len+i; //zero rest of payload (shifted)
    }
//    while(tempIndex <= packet_end)
//		*(tempIndex++) = '0';

    if(p)
    {
	//do NOT change IP length
//	if(p->iph) //change IP total length
//	    p->iph->ip_len = htons(ntohs(p->iph->ip_len) + shift);
//	if(p->udph) //change UDP length
//	    p->udph->uh_len =htons(ntohs(p->udph->uh_len) + shift);

	//DO NOT CHANGE actual length
//	last_header_seen->wlen +=shift;
	//CHANGE PCAP CAPLEN
	last_header_seen->caplen +=shift;

	//Fix application level decoding
	for(i=0;i<(p->num_of_upper_layer_protocols);i++)
	{
		if((p->upper_layer_names[i])==HTTP) 
		{
			struct httpheader *h=(struct httpheader *)(p->upper_layer_protocol_headers[i]);
			for(k=0;k<h->pipeline_depth;k++) {
			for(j=0;j<(END_HTTP_DEFS-BASE_HTTP_DEFS+1);j++) 
			{
				if((h->pointers_to_value[k][j])>field) 
					h->pointers_to_value[k][j] +=shift;
				if((h->pointers_to_header[k][j])>field) 
					h->pointers_to_header[k][j] +=shift;
			}
			}
		}
		else  if((p->upper_layer_names[i])==FTP) 
		{
			struct ftpheader *h=(struct ftpheader *)(p->upper_layer_protocol_headers[i]);
			for(j=0;j<(END_FTP_DEFS-BASE_FTP_DEFS+1);j++) 
			{
				if((h->pointers_to_value[j])>field) 
					h->pointers_to_value[j] +=shift;
				if((h->pointers_to_header[j])>field) 
					h->pointers_to_header[j] +=shift;
			}
		}
	}
    }

    return 0;
}

/************* REGULAR EXPRESSION **************/
#define PCRE_OVECTOR_SIZE 30
int reg_exp_substitute(unsigned char *field, int len, char *regular_expression, unsigned char **replacement_vector, int num_of_matches,mapipacket *p,int total_len,unsigned char *packet_end)
{
    pcre *re;
    int erroroffset;
    const char *error;
    int ovector[PCRE_OVECTOR_SIZE];
    int result;

    re=pcre_compile(regular_expression,PCRE_CASELESS,&error,&erroroffset,NULL);
    if(re==NULL)
	return -1;

    result = pcre_exec(re, NULL,(char *) field, len, 0, 0, ovector, PCRE_OVECTOR_SIZE);
    
    if(result > 0) //match
    {
	int i;
	if(result != (num_of_matches+1))
	    return -1;//not a proper match
	for (i = 1; i < result; i++)
	{
	    if(replacement_vector[i-1])
	    {
		unsigned char *substring_start = field + ovector[2*i];
		int substring_length = ovector[2*i+1] - ovector[2*i];
		replace_field(substring_start, substring_length, replacement_vector[i-1], strlen((char *)replacement_vector[i-1]), p, total_len , packet_end); 
	    }
	}
    }
    
    return 0;
}
