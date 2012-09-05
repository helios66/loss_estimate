#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

void hex_print(unsigned char *buf, int buflen, char *label)
{
	int i;
	int j;
	int k;

	for (i = 0, j = 0; i < buflen; i++, j++) {
		if (i == 0)
			printf("%s", label);
		else
			for (k = 0; k < strlen(label); k++)
				printf(" ");

		for (; i < buflen - 1 && i % 16 < 15; i++) {
			printf("%02x ", (unsigned char) buf[i]);
		}
		printf("%02x ", (unsigned char) buf[i]);

		if (buflen > 16)
			for (k = 0; (i + k) % 16 < 15; k++)
				printf("   ");
		for (; j < buflen - 1 && j % 16 < 15; j++) {
			printf(isprint(buf[j]) ? "%c" : ".", (unsigned char) buf[j]);
		}
		printf(isprint(buf[j]) ? "%c\n" : ".\n", (unsigned char) buf[j]);
	}

}

// Modifies the bufp argument to point to a buffer containing the parsed string.
// Returns the length of the buffer.
// The buffer has been allocated with malloc and must be freed by the caller.
int hex_parse(char *hex, unsigned char **bufp)
{
	char *token;
	char *hex_copy;
	unsigned char *buf = NULL;
	int buflen = 0;

	hex_copy = strdup(hex); // copy because strtok modifies input buffer

	token = strtok(hex_copy, " \n\t");
	while (token != NULL) {
		buflen++;
		buf = realloc(buf, buflen);
		buf[buflen - 1] = strtol(token, NULL, 16);
		token = strtok(NULL, " \n\t");
	}

	free(hex_copy);

	*bufp = buf;
	return buflen;
}
