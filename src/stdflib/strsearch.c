#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"
#include "debug.h"
#include "mapiipc.h"
#include "mstring.h"
#include "mapi_errors.h"

struct mapid_strsearch_pattern {
  unsigned char *str;   /* string to search for in payload (without '\0')*/
  int slen;    /* length of string */
  int offset;  /* Starting search position from the beginning of packet */
  int depth;   /* Maximum search depth from the beginning of search position */
  int *shift;  /* Boyer-Moore Shift table */
  int *skip;   /* Boyer-Moore Skip table */
  
  struct mapid_strsearch_pattern *next;
};

struct mapid_strsearch {
  struct mapid_strsearch_pattern *pattern;
  unsigned short num_patterns; // XXX: do we need to know how many patterns there are?

  unsigned long long currentIteration; // Optimization for packet in this iteration
  char result; // result of evaluation
};


short isEscaped(char *pos);

static int strsearch_instance(mapidflib_function_instance_t *instance,
			      MAPI_UNUSED int fd,
			      MAPI_UNUSED mapidflib_flow_mod_t *flow_mod)
{
  mapiFunctArg* fargs=instance->args;
  char *str = getargstr(&fargs);
  int offset = getargint(&fargs);
  int depth = getargint(&fargs);
 
  if(!str)
	  return MFUNCT_INVALID_ARGUMENT_1;

  if(str==NULL)  
    return MFUNCT_INVALID_ARGUMENT_1;
  else if(strlen(str) < 1)  // could also force a maximum length for the pattern
    return MFUNCT_INVALID_ARGUMENT_1;
  if(offset < 0)
    return MFUNCT_INVALID_ARGUMENT_2;
  if(depth < 0)
    return MFUNCT_INVALID_ARGUMENT_3;
  
  return 0;
}

// helper function for strsearch_init()
short isEscaped(char *pos) {
	int num_of_slashes=0;
	char *tmp;

	tmp=pos-1;
	while(*tmp=='\\') {
		tmp--;
		num_of_slashes++;
	}
	if(num_of_slashes%2==0)
		return 0;
	return 1;
}

static int strsearch_init(mapidflib_function_instance_t *instance,
			  MAPI_UNUSED int fd)
//Initializes the function
{
  char *str, *strbak;
  int off, dpth;

  unsigned char *tmpstr, *tstrbak;
  unsigned char *ret;	// holds the final parsed string
  int len=0;	// length of the final parsed string
  unsigned short pattern_ctr = 0;
  char hexpair[3];
  mapiFunctArg* fargs;
  struct mapid_strsearch_pattern *pattern = NULL;
  struct mapid_strsearch_pattern *lastptrn, *tmpptrn = NULL;

  fargs=instance->args;
  str = getargstr(&fargs);
  off = getargint(&fargs);
  dpth = getargint(&fargs);

  /* parse pattern
   * 
   * Non printable characters or general binary content can be specified by
   * using pipes enclosing the binary data which are represented in hex
   * values for each byte.  For example, 'abcd' is the same as '|61 62 63
   * 64|' or 'ab|63 64|' or '|61|b|6364|. If the pipe character needs to be
   * searched, it should be preceeded by a '\'.
   */
  
  strbak = str; // backup pointer
  tstrbak = tmpstr = (unsigned char *)malloc(strlen(str)*sizeof(char));
  ret=tmpstr;
  hexpair[2]='\0';  
  
  while(*str!='\0') {
    
    // Two pipes "||" separates two match strings. 
    // A||B will match both a packet with either A or B in it.
    if (*str == '|' && *(str+1) == '|') // Should be safe since last char will be '\0'
    {
      if (!isEscaped(str))
      {
        len=tmpstr-ret;
        if (len <= 0)
        {
          // Empty OR node, skip
          str += 2;
          continue;
        }
        if((dpth > 0) && (dpth < len))
        {
          DEBUG_CMD(Debug_Message("The depth (%d) is less than the size of the pattern (%d)", dpth, len));
          return MDLIB_STRSEARCH_DEPTH_LESS_THAN_PTRN_ERR;
        }
        
        tmpptrn = malloc(sizeof(struct mapid_strsearch_pattern));

        tmpptrn->str = (unsigned char *)malloc(len * sizeof(char));
        tmpptrn->slen = len;
        tmpptrn->offset = off;
        tmpptrn->depth = dpth;
        memcpy(tmpptrn->str, ret, len);
        //compute Boyer-Moore's shift and skip tables 
        tmpptrn->shift = make_shift((char *)ret, len);
        tmpptrn->skip = make_skip((char *)ret, len);
        tmpptrn->next = NULL;

        if (pattern == NULL)
        {
          pattern = tmpptrn;
          lastptrn = tmpptrn;
        }
        else
        {
          lastptrn->next = tmpptrn;
          lastptrn = tmpptrn;
        }

        tmpptrn = NULL;
        ret = tmpstr;
        pattern_ctr++;
      }
      else
      {
        *tmpstr=*str;
        tmpstr++;
      }
      str++;
    }
    
    // '|' means that hex mode begins unless it is escaped \|
    // every hex number consists of two characters ,e.g A is written as 0A
    else if(*str=='|') {
  		if(!isEscaped(str)) {
  			int hexcount=0;
  			str++;
  			//parse until closing '|'
  			while(*str!='|') {
  				if(*str=='\0') {
  					return MDLIB_STRSEARCH_UNTERMINATED_PIPE_ERR;
                }
  				// |AC DE| => ignore white spaces between hex numbers
  				if(*str==' ') {
  					str++;
  					continue;
  				}
  				//convert hex to character
  				hexpair[hexcount++]=*str;
  				if(hexcount==2) {
  					hexcount=0;
  					sscanf(hexpair,"%x",(int *)tmpstr);
  					tmpstr++;
  				}
  				str++;
  			}
  		}
  		else {
  			*tmpstr=*str;
  			tmpstr++;
  		}
  	}
  	// special case for escape character '\\'
  	else if(*str=='\\') {
  		if(isEscaped(str)) {
  			*tmpstr=*str;
  			tmpstr++;
  		}	
  	}
  	else {
  		*tmpstr=*str;
  		tmpstr++;
  	}
  	str++;
  }
  len=tmpstr-ret;	
  /* end of pattern parsing */

  /*
    Arne: Will fix it later

  funct = fhlp_get_first();
  while (funct) {
    if(strcmp(funct->name,"STR_SEARCH")==0)
      if(funct->internal_data)
	if(memcmp(((struct mapid_strsearch *)funct->internal_data)->str, ret, 
		  ((struct mapid_strsearch *)funct->internal_data)->slen) == 0)
	  if(((struct mapid_strsearch *)funct->internal_data)->offset == off &&
	     ((struct mapid_strsearch *)funct->internal_data)->depth == dpth){
	    instance->internal_data = funct->internal_data;
	    printf("added optimised string search: %s offset: %d depth: %d\n",strbak, off, dpth);
	    return 0;
	  }
    funct = funct->next;
  }
  */

  if((dpth > 0) && (dpth < len)){
    DEBUG_CMD(Debug_Message("The depth (%d) is less than the size of the pattern (%d)", dpth, len));
    return MDLIB_STRSEARCH_DEPTH_LESS_THAN_PTRN_ERR;
  }

  if (len > 0)
  {
    tmpptrn = malloc(sizeof(struct mapid_strsearch_pattern));

    tmpptrn->str = (unsigned char *)malloc(len * sizeof(char));
    tmpptrn->slen = len;
    tmpptrn->offset = off;
    tmpptrn->depth = dpth;
    memcpy(tmpptrn->str, ret, len);
    //compute Boyer-Moore's shift and skip tables 
    tmpptrn->shift = make_shift((char *)ret, len);
    tmpptrn->skip = make_skip((char *)ret, len);
    tmpptrn->next = NULL;

    if (pattern == NULL)
      pattern = tmpptrn;
    else
      lastptrn->next = tmpptrn;
    
    pattern_ctr++;
  }
  
  if (pattern == NULL)
  {
    // Invalid search term
    return MDLIB_STRSEARCH_NOT_A_VALID_SEARCH_STRING;
  }

  instance->internal_data = malloc(sizeof(struct mapid_strsearch));
/*
  ((struct mapid_strsearch *)instance->internal_data)->str = (unsigned char *)malloc(len * sizeof(char));
  ((struct mapid_strsearch *)instance->internal_data)->slen = len;
  ((struct mapid_strsearch *)instance->internal_data)->offset = off;
  ((struct mapid_strsearch *)instance->internal_data)->depth = dpth;
  memcpy(((struct mapid_strsearch *)instance->internal_data)->str, ret, len);
  //compute Boyer-Moore's shift and skip tables 
  ((struct mapid_strsearch *)instance->internal_data)->shift = make_shift((char *)ret, len);
  ((struct mapid_strsearch *)instance->internal_data)->skip = make_skip((char *)ret, len);
*/
  ((struct mapid_strsearch *)instance->internal_data)->pattern = pattern;
  ((struct mapid_strsearch *)instance->internal_data)->num_patterns = pattern_ctr;
  ((struct mapid_strsearch *)instance->internal_data)->currentIteration = 0;
  DEBUG_CMD(Debug_Message("added string search: %s offset: %d depth: %d nodes: %u", strbak, off, dpth, pattern_ctr));
  
  free(tstrbak);
  
  return 0;
}

static int strsearch_process(mapidflib_function_instance_t *instance,
			     MAPI_UNUSED unsigned char* dev_pkt,
			     unsigned char* pkt,
			     mapid_pkthdr_t* pkt_head)  
{
  int len;
  struct mapid_strsearch_pattern *pattern;

  //Check if this packet is allready evaluated in this iteration
  //Yes => return result
  if (((struct mapid_strsearch *)instance->internal_data)->currentIteration == instance->hwinfo->pkts){
    return ((struct mapid_strsearch *)instance->internal_data)->result;
  }

  //No => evaluate
  else ((struct mapid_strsearch *)instance->internal_data)->currentIteration = instance->hwinfo->pkts;
  
  ((struct mapid_strsearch *)instance->internal_data)->result = 0;

  pattern = ((struct mapid_strsearch *)instance->internal_data)->pattern;

  while (pattern != NULL)
  {
    len = pkt_head->caplen - pattern->offset;

    if(pattern->depth && (len > pattern->depth))
      len = pattern->depth;
    if(len < pattern->slen)
      return ((struct mapid_strsearch *)instance->internal_data)->result;

    if (mSearch((char *)(pkt+pattern->offset), len, (char *)pattern->str, pattern->slen,
        pattern->skip, pattern->shift))
      return (((struct mapid_strsearch *)instance->internal_data)->result = 1);

    pattern = pattern->next;
  }

  return ((struct mapid_strsearch *)instance->internal_data)->result;
}

static int strsearch_cleanup(mapidflib_function_instance_t *instance) 
{
  struct mapid_strsearch_pattern *pattern, *tmp;
  
  if(instance->internal_data != NULL){
    pattern = ((struct mapid_strsearch *)instance->internal_data)->pattern;
    while (pattern != NULL)
    {
      if(pattern->str != NULL)
        free(pattern->str);
      if(pattern->shift != NULL)
        free(pattern->shift);
      if(pattern->skip != NULL)
        free(pattern->skip);
      tmp = pattern->next;
      free(pattern);
      pattern = tmp;
    }
    free(instance->internal_data);
  }
  return 0;
}

static mapidflib_function_def_t finfo={
  "",
  "STR_SEARCH",
  "Searches a packet for a string\nParameters:\n\tsearch pattern : char*\n\toffset : int\n\tdepth : int",
  "sii",
  MAPI_DEVICE_ALL,
  MAPIRES_NONE,
  0, //shm size
  0, //modifies_pkts
  1, //filters packets
  MAPIOPT_AUTO, //Optimization
  strsearch_instance,
  strsearch_init,
  strsearch_process,
  NULL, //get_result
  NULL, //reset
  strsearch_cleanup,
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* strsearch_get_funct_info();
mapidflib_function_def_t* strsearch_get_funct_info() {
  return &finfo;
};



