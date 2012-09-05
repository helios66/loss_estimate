/* (C) Akritid, All Rights Reserved
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include "mod_detect.h"
#include "offset_info.h"

#define dprintf(...) 

#define RELAX_SELF_MODIFICATION

static void print_ins(unsigned char *buf, int size, char *mnemonic)
{
	int n;
	for (n = 0; n < 12; n++) {
		if (n < size)
			dprintf("%02X ", buf[n]);
		else
			dprintf("   ");
	}
	dprintf("%s", mnemonic);

}


/*
 * Alrternative analyzer based on "Abastract Payload Execution" paper.
 */
static int analyze_ape(unsigned char *buf, int bufsize, int pos, struct offset_info *info)
{
	trieptr r;
	int size;

	size = decode_ape(buf + pos, bufsize - pos, &r);
	if (r == NULL) {
		info->outcome = 'i';
		return 0;
	} else if (r->jump) {
		info->outcome = 'j';
		if (r->jump == 'c') {
			int difference = getPositionDifference(r, buf, pos);
			info->is_branchcc = 1;
			info->branch = pos + size + difference;
		}

		return 0;
	} else {
#ifdef ANALYZE_RECORD 
		if (analyzeRecord(r, buf, pos, bufsize) == 1)
			return 0;
#endif
		return size;
	}
}



void decoder_init(void)
{
	detect_init();
}


int analyze(unsigned char *buf, int bufsize, int pos, struct offset_info *info)
{
	return analyze_ape(buf, bufsize, pos, info);
}

void decoder_cleanup(void)
{
	return;
}
