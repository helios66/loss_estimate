/*
 * NO MULTIPLE FILES
 * Converts tsh input file to multiple output files (depending on 
 * size of input file) that can be read using libpcap.
 * 
 * If multimple files are generated, then only the first
 * includes the file header, all the rest have plain
 * pcap-packets.
 * This assists cat-ing them on a libpcap stdin reader
 * 
 * Uses a template file as a parameter in order to
 * set the parameters of the output files (linktype, ...)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>

typedef unsigned int bool;
#define true 1
#define false 0
#define SNAPLEN	68

void assertNull( void * mem, char * msg ) {
	if (mem == NULL) { fprintf(stderr, "%s\n", msg); exit(1); }

}

pcap_dumper_t * getOutputFile(pcap_t * ifile, char *infile) {
	char * ofilename;
	pcap_dumper_t* pdumper;
	int ofilelen=0;

	//set filename
	ofilelen = strlen(infile)-4;
	if (ofilelen <= 0 || infile[ofilelen] != '.') {
		fprintf(stderr, "Input tsh file must have a .tsh suffix [%d %c]\n", ofilelen, infile[ofilelen]);
		exit(23);
	}
	ofilename = (char * ) calloc ( ofilelen+1, sizeof (unsigned char));
	assertNull ( ofilename, "Failed to create output filename(s)" );
	strncpy (ofilename, infile, ofilelen);
	ofilename[ofilelen] = '\0';
	fprintf (stderr,"\nCreating %s\n", ofilename);

	//open output file
	pdumper = pcap_dump_open(ifile, ofilename); //get output file specifications from input file
	assertNull(pdumper, "Failed to open output file(s)");

	return pdumper;
}

struct pcap_timeval {
    bpf_int32 tv_sec;		/* seconds */
    bpf_int32 tv_usec;		/* microseconds */
};

struct pcap_sf_pkthdr {
    struct pcap_timeval ts;	/* time stamp */
    bpf_u_int32 caplen;		/* length of portion present */
    bpf_u_int32 len;		/* length this packet (off wire) */
};

//copies the headers described in tsh
//after the ethernet frame header (which starts at pos 14)
//also sets the ethernet frame type to IP
int setHeaders (unsigned char * packet, unsigned char * tsh) {
	int i = 0;
	unsigned int IPHLBytes;

	//Ethernet frame type : IP
	packet[12] = 0x8;
	packet[13] = 0x0;

	//append ip
	IPHLBytes  = (tsh[8] & 0xF) * 4;
	while (i<20) {
		packet[14+i] = tsh[8+i];
		i++;
	}
	while (i<IPHLBytes) {
		//append options (zero)
		packet[14+i] = 0;
		i++;
	}
	//append TCP
	while (i<IPHLBytes+16) {
		packet[14+i] = tsh[8+i-(IPHLBytes-20)];
		i++;
	}

	return (i+14);
}
void setPayload(unsigned char * packet, unsigned int off, unsigned int len) {
	int i=0;
	unsigned long randoms[500];
	unsigned char * rchars;
	//generate some randoms
	for (i=0; i<500; i++) randoms[i] = random();
	rchars = (unsigned char *) randoms;

	//put them in place
	for (i=off+16; i<len; i++) {
		packet[i] = rchars[i%500];
	}
	return;
}


int main(int argc, char * argv[]) {
	char * ebuf;
	char * fn;
	char * fn2;
	pcap_t * ifile;
	FILE * ifile2;
	struct pcap_pkthdr *  pktHeader = NULL;
	u_char * fullpacket;
	pcap_dumper_t * pdumper;
	unsigned char tsh[44];
	int readCount;
	unsigned long packetNo;
	unsigned long skipped = 0;
	unsigned long long bytesWritten = 0;

	/*
		Initialize random generator
	*/
	srandom ( time(NULL) );

	/*
	   parse command line arguements
	*/
	if (argc != 3) {
		printf ("Usage: %s inputfile1_pcap inputfile2.tsh\n", argv[0]);
		return 1;
	} else {
		fn = argv[1];
		fn2 = argv[2];
	}

	/*
	  Gather mem
	*/
	fullpacket = malloc (2000*sizeof(unsigned char));
	assertNull (fullpacket, "No mem for fullpacket\n");

	pktHeader = malloc (sizeof(struct pcap_pkthdr));
	assertNull (pktHeader, "No mem pktHeader");
	
	ebuf = malloc( PCAP_ERRBUF_SIZE );
	assertNull( ebuf, "No mem for ebuf" );

	/* 
	   open input file : pcap sample file
    */
	ifile = pcap_open_offline(fn, ebuf);
	assertNull ( ifile, "Error opening file\n" );


	/*
		Open input file : tsh file
	*/
	ifile2 = fopen (fn2, "r");
	assertNull (ifile2, "Couldn't open sec file\n");

	
	/*
	   open output file
    */
	pdumper = getOutputFile(ifile, argv[2]);

	/*
		Main Loop -- Iteration for every packet ---
	*/
	packetNo = 0;
	readCount = fread (tsh, sizeof (unsigned int), 11, ifile2);
	while (readCount == 11) {

		unsigned int ipVer;
		unsigned int IPHL;
		unsigned int totByteLen;
		unsigned int payloadOffset;

		//progress indicator
		     if ( (packetNo%1000000) == 0) { fprintf (stderr, "|"); fflush (stderr); }
		else if ( (packetNo%100000) == 0) { fprintf (stderr, "."); fflush (stderr); }

		//form data from input
		ipVer = (tsh[8] & 0xF0) >> 4;
		IPHL  = (tsh[8] & 0xF) * 4;
		if (ipVer != 4) printf ("X");
		totByteLen = (tsh[10] << 8) | tsh[11];
		//ok printf ("%d\n", totByteLen);
		if (totByteLen > 1554 || totByteLen < 16) {
			//ooops!
			skipped++;
			goto NEXT;
		}
		
		//prepare data for pcap_dump
		//only necessary data are set. (See savefile.c pca_dump(...) implementation)
		pktHeader->ts.tv_sec = (tsh[0] << 24) |
							   (tsh[1] << 16) |
							   (tsh[2] << 8) |
							    tsh[3];
		pktHeader->ts.tv_usec = (tsh[5] << 16) |
							    (tsh[6] << 8) |
							     tsh[7];
		pktHeader->caplen = SNAPLEN;
		pktHeader->len = totByteLen + 14;

		payloadOffset = setHeaders(fullpacket, tsh);
		if (payloadOffset>50) printf ("O");
		//printf ("%d\n", payloadOffset);
		setPayload (fullpacket, payloadOffset, SNAPLEN);

		pcap_dump((unsigned char*)pdumper, pktHeader, fullpacket);
		bytesWritten += totByteLen + 14;
/*
 * Don't care about max file size ...
 *
		if (bytesWritten>1950000000) {
			fprintf(stderr, "Aborting: output file is too big\n");
			break;
		}
*/
		NEXT:
		readCount = fread (tsh, sizeof (unsigned int), 11, ifile2);
		packetNo++; 
		//if (packetNo == 10000) break;
	}
	printf("\n");

	printf ("Counted %lu packet headers\n", packetNo);
	printf ("Skipped %lu packet headers\n", skipped);
	printf ("File size %llu\n", bytesWritten);


	
	//Close files
	pcap_close(ifile);
	fclose(ifile2);
	pcap_dump_close(pdumper);

	return 0;
}

