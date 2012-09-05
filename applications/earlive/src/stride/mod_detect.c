 /* 
 * Apache code detector module - detects buffer overflow exploits
 * containing NOP equivalent sledges and prevents malicious requests
 * from being executed.
 * 
 * Author: Thomas Toth
 *         ttoth@infosys.tuwien.ac.at
 *
 */

#include "defines.h"
#include "mod_detect.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* Data declarations.                                                       */
/*                                                                          */
/* Here are the static cells and structure declarations private to our      */
/* module.                                                                  */
/*                                                                          */
/*--------------------------------------------------------------------------*/


// Data declarations and definitions

static trieptr myTrie;
static int max_length;

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* These routines are strictly internal to this module, and support its     */
/* operation.  They are not referenced by any external portion of the       */
/* server.                                                                  */
/*                                                                          */
/*--------------------------------------------------------------------------*/

static void error(char * string) {
  fprintf(stderr,"%s\n",string);
  exit(1);
}


static int timedif(struct timeval a, struct timeval b)
{
    register int us, s;

    us = a.tv_usec - b.tv_usec;
    us /= 1000;
    s = a.tv_sec - b.tv_sec;
    s *= 1000;
    return s + us;
}

static void checkEndOfString(char * string) {
  if (*string==0)
    error("Malformed string, encountered unexpected end of string.");
}

static char * getEndOfTokenMultiple(char * string, char * delimiters) {
  int delimiterfound=0;
  char * del1;

  while (!delimiterfound) {
    del1=delimiters;

    while (*del1!=0) {
      if (*del1==*string) {
	delimiterfound=1;
	break;
      }
      del1++;
    }
    
    if (delimiterfound)
      break;

    // End of string reached
    if (*string==0)
      break;

    string++;
  }
  return string;
}


static char * getStartOfOpcode(char * string) {

  while(*string!='#') {
    string++;
    checkEndOfString(string);
  }

  string++;
  checkEndOfString(string);

  while(*string!='#') {
    string++;
    checkEndOfString(string);
  }

  string++;
  checkEndOfString(string);

  while (*string==' ') {
    string++;
    checkEndOfString(string);
  }

  return string;
}

static char * getStartOfNextOpcode(char * string) {
  while (*string!=' ')
    string++;

  while (*string==' ')
    string++;

  return string;
}

static void clear_node(trieptr ptr) {
  int i=0;

  ptr->number_of_operands=0;
  ptr->operands=NULL;
  ptr->is_leaf=0;
  ptr->line=NULL;
  ptr->jump=0;
  for (i=0;i<256;i++)
    ptr->triefollowers[i]=NULL;
}

static trieptr new_trie_node(int nr_of_operands,int *ops, char * string, int opcode_length, unsigned char jump) {
  int i=0;
  trieptr ptr;

  if ((ptr=(trieptr) malloc(sizeof(struct trienode)))==NULL) {
    error("Malloc: could not make new node"); 
  }
  
  ptr->number_of_operands=nr_of_operands;
  ptr->operands=ops;
  ptr->is_leaf=1;
  ptr->line=string;
  ptr->jump=jump;
  ptr->opcode_length=opcode_length;
  for (i=0;i<256;i++)
    ptr->triefollowers[i]=NULL;

  return ptr;
}

static void printTrieRecord(trieptr trie) {
  int i;

  fprintf(stderr,"\nTrierecord:\n==========\n");
  fprintf(stderr,"%s\n",trie->line);
  fprintf(stderr,"Number of opcodes: %d\n",trie->opcode_length);
  fprintf(stderr,"%d Operands: ", trie->number_of_operands);
  fflush(stdout);
  for (i=0;i<trie->number_of_operands;i++) {
    fprintf(stderr,"%d ",trie->operands[i]);
    fflush(stderr);
  }
  if (trie->jump!=0) 
    fprintf(stderr,"jumps: %c\n",trie->jump);
  fprintf(stderr,"\n");
  fflush(stderr);

}

static void printTrie(trieptr trie) {
  int i=0;

  if (trie==NULL)
    return;
  if (trie->is_leaf==1) {
    printTrieRecord(trie);    
  }

  for (i=0;i<256;i++) {
    if (trie->triefollowers[i]!=NULL) {
      fprintf(stderr,"down: %02x\n",i);
      printTrie(trie->triefollowers[i]);
      fprintf(stderr,"up: %02x\n",i);
    }
  }
}

static trieptr insertString(trieptr trie, int number_of_opcode_bytes,int original_opcode_bytes,int * opcode, int number_of_args,int * args, char * string, unsigned char jump) {
  
  if (trie==NULL) {
    if ((trie = (trieptr) malloc(sizeof(struct trienode)))==NULL) {
      error("Could not malloc!");
    } else {
      clear_node(trie);
    }
  }
  
  if (number_of_opcode_bytes>1) {
    trie->triefollowers[*opcode]=insertString(
					      trie->triefollowers[*opcode], 
					      number_of_opcode_bytes-1, 
					      original_opcode_bytes,
					      opcode+1, 
					      number_of_args,
					      args,
					      string,
					      jump);
  }
  else {
    if (trie->triefollowers[*opcode]!=NULL) {
      if (trie->triefollowers[*opcode]->is_leaf!=0) {
      }
      else {
	trie->triefollowers[*opcode]->is_leaf=1;
	trie->triefollowers[*opcode]->number_of_operands=number_of_args;
	trie->triefollowers[*opcode]->operands=args;
	trie->triefollowers[*opcode]->line=string;
	trie->triefollowers[*opcode]->opcode_length=original_opcode_bytes;
	trie->triefollowers[*opcode]->jump=jump;
      }
    }
    else {
      trie->triefollowers[*opcode]= new_trie_node(number_of_args, args, string, original_opcode_bytes,jump);  
    }
    
  }
  
  return trie;
}

static trieptr searchtrie(trieptr ptr, unsigned char * code, int max_bytes) {
  trieptr hptr=NULL;

  int i;
  
  if (ptr==NULL)
    return NULL;


  while (max_bytes>0) {
    hptr = ptr->triefollowers[*code];

    if (hptr!=NULL) {
      if (hptr->is_leaf==1)
	return hptr;
      else {
	ptr=hptr;
	code=code+1;
	max_bytes--;
      }
    }
    else
      return NULL;
  }
  return NULL;
}

static int getNumberOfOperands(trieptr trie) {
 return trie->number_of_operands;
}

static int getIthOperand(trieptr trie, int nr) {
  if (nr>trie->number_of_operands)
    error("Error: could not access operand which is out of range.");

  return trie->operands[nr];
}

static int getAmountOfComsumedBytes(int type) {
  switch(type) {
  case I1:
  case BV1:
  case REL8:
  case REGREL8:
    return 1;
  case I2:
  case BV2:
  case REL16:
    return 2;
  case I4:
  case BV4:
  case REL32:
    return 4;    
  }
}

static int getSkip(trieptr result) {
  int opcode_length;
  int nr_of_operands;
  int *operands;
  int skip=0;
  int i;

  if (result==NULL) {
    fprintf(stderr,"Got NULL record");
    return -1;
  }


  opcode_length=result->opcode_length;
  nr_of_operands=result->number_of_operands;
  operands=result->operands;
  skip=skip+opcode_length;
  
  for (i=0;i<nr_of_operands;i++) {
    skip=skip+getAmountOfComsumedBytes(operands[i]);
  }
  return skip;
}

long getPositionDifference(trieptr result, unsigned char * bytes, int counter) {

  char *char_ptr;
  int *int_ptr;
  long *long_ptr;

  if (result->number_of_operands!=1) {
    error("Assumption does not hold that jump has only one parameter!");
  }
  
  switch (result->operands[0]) {
  case REL8:
    char_ptr =bytes+counter+result->opcode_length;
    return *char_ptr;
    break;
  case REL16:
    int_ptr =(int*) bytes+counter+result->opcode_length;
    return *int_ptr;
    break;
  case REL32:
    long_ptr = (long *) (bytes+counter+result->opcode_length);
    return *long_ptr;
    break;
    
  default:
  	;
    // akritid
    //fprintf(stderr, "Found operator %d in a jump directive.",result->operands[0]);
  }
}

static int getMax(int a, int b) {
  if (a>b)
    return a;
  else 
    return b;
}

int analyzeRecord(trieptr r, unsigned char * bytes, int index, int length) {
  int i;
  long * long_ptr;


  int current_counter=index+r->opcode_length;
  if (current_counter>length)
    return 0;

  for (i=0;i<r->number_of_operands;i++) {
    switch(r->operands[i]) {
    case REGREL8:
    case REL8:
    case I1:
    case BV1:
      current_counter=current_counter+1;
      break;
    case REGREL16:
    case REL16:
    case I2:
    case BV2:
      current_counter=current_counter+2;
      break;
    case BV4:
      long_ptr = (long *) (bytes+current_counter);
      if (abs((long) (long_ptr-0xbfff0000))>length)
	return 1;
      current_counter=current_counter+4;
      break;
    case I4:
    case REL32:
    case REGREL32:
      current_counter=current_counter+4;
      break;
    default:
      fprintf(stderr,"ERROR: Switch statement in analyze record");
      exit(1);
    }
  }

  return 0;
}

static int get_ei(trieptr trie, unsigned char * bytes, int length, int startvalue,int bound, int startindex) {
  int counter=0;
  trieptr result;
  int successful_instructions=0;

#ifdef APE_DETAILS
  printf("Entering get_ei for startvalue %d startindex %d\n", startvalue, startindex);
#endif

  counter=startindex;
  successful_instructions=startvalue;

  if (counter>length || counter < 0)
    return successful_instructions;


  while (counter<length ) {

    if (successful_instructions>=bound) {
      //fprintf(stderr,"Limit reached.\n");
      return successful_instructions;
    }

    result=searchtrie(trie,bytes+counter,length-counter);

    if (result==NULL) {
#ifdef APE_DETAILS
  printf("Illegal, Returning %d\n", successful_instructions);
#endif
      return successful_instructions;
    }
    else {

      if (result->jump!=0) {

	switch (result->jump) {
	case 'u':
	  {
	    long difference;
	    int skip;

	    difference =getPositionDifference(result,bytes,counter);
	    if ((counter+difference+getSkip(result)<0) ||
		(counter+difference+getSkip(result)>length))
	      return successful_instructions;
	    skip=getSkip(result);

#ifdef APE_DETAILS
  printf("Recursion for 'u'\n");
#endif
	    successful_instructions=
	      get_ei(trie, 
		     bytes,
		     length,
		     successful_instructions+1,
		     bound, 
		     counter+skip+difference);
	  }
	  
#ifdef APE_DETAILS
  printf("After 'u', Returning %d\n", successful_instructions);
#endif
	  return successful_instructions;
	  break;
	case 'c':
	  {
	    long difference;
	    difference =getPositionDifference(result,bytes,counter);

#ifdef APE_DETAILS
  printf("Recursion for 'c'\n");
#endif
	    successful_instructions=
	      getMax(
		     get_ei(
						       trie, 
						       bytes,
						       length,
						       successful_instructions+1,
						       bound, 
						       counter+getSkip(result)+difference),
		     get_ei(
						       trie, 
						       bytes,
						       length,
						       successful_instructions+1,
						       bound, 
						       counter+getSkip(result)));	   
	  }	  

#ifdef APE_DETAILS
  printf("After 'c', Returning %d\n", successful_instructions);
#endif

	  return successful_instructions;
	  break;

	case 'a':

#ifdef APE_DETAILS
  printf("After 'a', Returning %d\n", successful_instructions);
#endif
	  return successful_instructions+1;
	  break;
	default:
	  fprintf(stderr,"Error: do not know how to handle a record with '%c' as jump option, quitting out.",result->jump);
	}
      }
      else {
	if(analyzeRecord(result,bytes,counter,length)==1) {
	  return successful_instructions;
	}
	
	counter=counter+getSkip(result);
	successful_instructions++;
      }
      
    }
  }
  return successful_instructions;
}


// Choose a number of starting points within the code and try to make nr_of_tests tests. A test is valid if the number of instructions is once larger than nr_of_instructions.
static int test_n(trieptr trie, unsigned char * bytes,int bytecode_size, int nr_of_instructions, int nr_of_tests) 
{
  int i=0;
  int position=0;
  int executable_instructions=0;

  for (i=0;i<nr_of_tests;i++) {
    struct timeval time;
    gettimeofday(&time,0);
    srand(time.tv_usec+time.tv_sec+i*10000);
    position = 1+(int) (((float) bytecode_size-nr_of_instructions)*rand()/(RAND_MAX+1.0));

    executable_instructions= get_ei(
				   trie,
				   bytes,
				   bytecode_size,
				   0,
				   nr_of_instructions,
				   position);


    if (executable_instructions>=nr_of_instructions) {
      fprintf(stderr,"\n****Found possible buffer overflow code at position %d.\n\n",position);
      return 1;
    }
  }
  return 0;
}

static int test_n_per_kb(trieptr trie, unsigned char * bytes,int bytecode_size, int nr_of_instructions, int nr_of_tests_per_kilobyte) 
{
  int i=0, j=0;
  int position=0;
  int kilobytes;
  int rest;
  int resttests;

  kilobytes = bytecode_size / 1024;

  for (j=0;j<kilobytes;j++) {
    if (
	test_n(trie, bytes+j*1024,1024, nr_of_instructions, nr_of_tests_per_kilobyte)
	==1)
      return 1;
  }

  rest = bytecode_size - kilobytes*1024;
  resttests = ((float) nr_of_tests_per_kilobyte * rest / 1024);
  if (
      test_n(trie, bytes+kilobytes*1024,rest, nr_of_instructions, resttests)
      ==1)
    return 1;

  return 0;
}

trieptr buildTrie(char * filename) {
  FILE * inputfile;
  trieptr myTrie=NULL;
  char buffer[1024];
  char * tmpstring;
  int i;
  int number_of_opcode_bytes;
  int number_of_args;
  int opcode[10];
  int *args;

  if ((inputfile=fopen(filename,"rt"))==NULL) {
      error("mod_detect: Could not open inputfile");
  }

  while (!feof(inputfile)) {
    char * stringptr=NULL;
    unsigned char * opcodes[16];

    bzero(buffer,1024);

    if (fgets(buffer, 1024, inputfile)==NULL) {
      break;
    }

    tmpstring=(char *) malloc(strlen(buffer)+1);
    if (tmpstring==NULL) {
      fprintf(stderr, "mod_detect: Could not Malloc for tmpstring");
    }
    else {
      strcpy(tmpstring,buffer);
      *(tmpstring+strlen(buffer))=0;
    }

    stringptr= getStartOfOpcode(buffer);

    sscanf(stringptr,"%d", &number_of_opcode_bytes);
    stringptr=getStartOfNextOpcode(stringptr);
    
    for (i=0;i<number_of_opcode_bytes;i++) {
      sscanf(stringptr,"%x",opcode+i);
      stringptr=getStartOfNextOpcode(stringptr);
    }

    sscanf(stringptr,"%d", &number_of_args);
    
    if (number_of_args>0)
      stringptr=getStartOfNextOpcode(stringptr);

    if ((args = malloc(sizeof(int)*number_of_args))==NULL) {
      error("Malloc for tmpstring");
    }

    for (i=0;i<number_of_args-1;i++) {
      sscanf(stringptr,"%d",args+i);
      stringptr=getStartOfNextOpcode(stringptr);
    }
    
    if (number_of_args>0)
      sscanf(stringptr,"%d",args+number_of_args-1);

    stringptr = getEndOfTokenMultiple(stringptr, "#\10");
    if (*stringptr==10 || *stringptr==0) {
      myTrie=insertString(myTrie, number_of_opcode_bytes,number_of_opcode_bytes, opcode, number_of_args,args, tmpstring,0);
    }
    else {
      stringptr++;
      while (*stringptr==' ')
	stringptr++;

      myTrie=insertString(myTrie, 
			  number_of_opcode_bytes,
			  number_of_opcode_bytes, 
			  opcode, 
			  number_of_args,
			  args, 
			  tmpstring,
			  *stringptr);      
    }
  }

  fprintf(stderr, "Finished reading of file\n");

  return myTrie;
}


/*
 * All our module-initialiser does is build up the trie.
 */
void detect_init()
{

  myTrie=NULL;
  max_length=0;
  if (myTrie==NULL) {
    fprintf(stderr,"Building up trie....\n");
    myTrie = buildTrie("detect.data");
  }
  else {
    fprintf(stderr,"Not building up trie, because it already exists\n");
  }
}

void doHexDump(char * ptr,int length, char * string) {
  int i;

  fprintf(stderr,"Hex Dump of %s:\n",string);
  for (i=0;i<13+strlen(string);i++)
    fprintf(stderr,"=");

  fprintf(stderr,"\n");
  
  for (i=0;i<length;i++) {
    if (i%16==0)
      fprintf(stderr,"\n%08x ",i);
    else
      if (i%8==0)
	fprintf(stderr,"   ");
    
    fprintf(stderr,"%02x ",(unsigned char) *(ptr+i));
  }
  
  fprintf(stderr,"\nEnd of HexDump\n\n");  
}


// Apply multiple tests to consequtive offsets. A test is valid if the number of instructions is once larger than nr_of_instructions.
static int test_markatian(trieptr trie, unsigned char * bytes,int bytecode_size, int nr_of_instructions, int nr_of_sequences) 
{
  int i = 0;
  int position = 0;
  int executable_instructions = 0;
  int consequtive_sequences = 0;

  for (i = 0; i < bytecode_size; i++) {
	position = i;

	executable_instructions= get_ei(
					trie,
					bytes,
					bytecode_size,
					0,
					nr_of_instructions,
					position);


	if (executable_instructions >= nr_of_instructions) {
		consequtive_sequences++;
	} else {
		consequtive_sequences = 0;
	}

	if (consequtive_sequences >= nr_of_sequences) {
		fprintf(stderr,"\n****Found possible buffer overflow code at position %d.\n\n",position);
		return 1;
	}
  }
  return 0;
}




int detect_sled(char *s, int len)
{
  struct timeval start;
  struct timeval end;
  //int nr_of_instructions = 35;
  int nr_of_instructions = MEL_THRESHOLD;

  gettimeofday(&start,0);

  if (len < nr_of_instructions)
	  return 0;
#if 1
  if (test_n_per_kb(myTrie, s, len, nr_of_instructions,100)) {
#else
  if (test_markatian(myTrie, s, len, nr_of_instructions,1)) {
#endif
    gettimeofday(&end,0);
    fprintf(stderr,"\nHandled in %d milliseconds\n",timedif(start,end));
    return 1;
  } else {
    return 0;
  }
}


int decode_ape(unsigned char *code, int max_bytes, trieptr *result)
{

	*result = searchtrie(myTrie, code, max_bytes);

	if (*result) {
		return getSkip(*result);
	} else {
		return 0;
	}
}

#ifdef MOD_DETECT_MAIN 
int main(int argc, char **argv)
{
	detect_init();

	if (detect_sled(argv[1], strlen(argv[1]))) {
		fprintf(stderr, "Found sled\n");
	}
}
#endif
