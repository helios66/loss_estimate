#ifndef OFFSET_INFO_H
#define OFFSET_INFO_H

struct offset_info {
	int is_decoded;
	
	char outcome;
	int resolved_at; // can be > bufsize !!!
	int sled; // is_sled

	unsigned int seq_len; // (unsigned) -1 means assume attack

	char mnemonic[16]; // mnemonic of instruction at this offset
	int size; // size of instruction at this offset

	int is_branchcc;
	int is_branch;
	int branch;
	int branchtree;
};

#endif
