#ifndef MOD_DETECT_H
#define MOD_DETECT_H

#define MEL_THRESHOLD	35
struct trienode {
  int is_leaf;
  int number_of_operands;
  int * operands;
  struct trienode * triefollowers[256];
  char * line;
  char opcode_length;
  unsigned char jump;
};

typedef struct trienode * trieptr;

int decode_ape(unsigned char *code, int max_bytes, trieptr *result);
void detect_init(void);
int detect_sled(char *s, int len);

#endif
