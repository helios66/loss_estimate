#ifndef STRIDE_H
#define STRIDE_H

void stride_init(void);

int stride_process(unsigned char *buf, int bufsize, int align, int slen, int, int);

void stride_cleanup(void);

void print_info(int bufsize);

#endif
