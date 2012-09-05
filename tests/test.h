
#define DOT  do{char UsElEsS[4]="\\|-/";\
	int urnotgoingusethis; \
	for( urnotgoingusethis=0; urnotgoingusethis<128; urnotgoingusethis++){\
		usleep(8);\
		fprintf(stderr,"%c" , UsElEsS[urnotgoingusethis%4]);\
		fprintf(stderr,"\b");\
		fflush(stderr);\
	}\
 fprintf(stderr, ".");fflush(stderr);\
}while(0)
