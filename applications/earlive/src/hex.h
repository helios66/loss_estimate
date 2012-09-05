#ifndef HEX_H
#define HEX_H

void hex_print(unsigned char *buf, int buflen, char *label);
int hex_parse(char *hex, unsigned char **bufp);

#endif
