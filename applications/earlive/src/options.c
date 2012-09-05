#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

/* Flag set by --verbose. */
int verbose_flag;
int config_skip_nul;

int config_target_threshold;
int config_cache_size;
int config_substring_length;
int config_flow_limit;
u_int32_t config_select_mask;
char *config_trace = NULL;
char *config_device = NULL;
char *config_bpf = NULL;
char *config_homenet = NULL;

int config_ear_enabled = 1;
int config_stride_enabled = 0;
int config_stride_flow_depth = 1000;
int config_stride_sled_length = 500;


void get_options(int argc, char **argv)
{
	int c;

	while (1) {
		static struct option long_options[] = {
			/* These options set a flag. */
			{"verbose", no_argument, &verbose_flag, 1},
			{"skip-nul", no_argument, &config_skip_nul, 1},
			/* These options don't set a flag.
			   We distinguish them by their indices. */
			{"help", no_argument, 0, 'h'},
			{"offset", required_argument, 0, 'f'},
			{"home-net", required_argument, 0, 'n'},
			{"period", required_argument, 0, 'p'},
			{"select-mask", required_argument, 0, 's'},
			{"targets", required_argument, 0, 't'},
			{"length", required_argument, 0, 'l'},
			{"disable-ear", no_argument, &config_ear_enabled, 0},
			{"enable-stride", no_argument, &config_stride_enabled, 1},
			{"stride-flow-depth", required_argument, 0, 1},
			{"stride-sled-length", required_argument, 0, 2},
			{0, 0, 0, 0}
		};
		/* getopt_long stores the option index here. */
		int option_index = 0;

		c = getopt_long(argc, argv, "f:l:p:s:r:ht:i:n:",
						long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c) {
		case 0:
			/* If this option set a flag, do nothing else now. */
			if (long_options[option_index].flag != 0)
				break;
#if 0
			printf("option %s", long_options[option_index].name);
			if (optarg)
				printf(" with arg %s", optarg);
			printf("\n");
#endif
			break;

		case 1: // --stide-flow-depth
			config_stride_flow_depth = atoi(optarg);
			break;
		case 2: // --stride-sled-length
			config_stride_sled_length = atoi(optarg);
			break;

		case 't':
			//printf("option -t with value `%s'\n", optarg);
			config_target_threshold = atoi(optarg);
			break;

		case 'f':
			//printf("option -f with value `%s'\n", optarg);
			config_flow_limit = atoi(optarg);
			break;

		case 'l':
			//printf("option -l with value `%s'\n", optarg);
			config_substring_length = atoi(optarg);
			break;

		case 's':
			//printf("option -s with value `%s'\n", optarg);
			//config_select_mask = strtol(optarg, (char **)NULL, 16);
			sscanf(optarg, "%x", &config_select_mask);
			break;

		case 'p':
			//printf("option -c with value `%s'\n", optarg);
			config_cache_size = atoi(optarg);
			break;

		case 'r':
			//printf("option -r with value `%s'\n", optarg);
			config_trace = strdup(optarg);
			break;

		case 'n':
			//printf("option -n with value `%s'\n", optarg);
			config_homenet = strdup(optarg);
			break;

		case 'i':
			//printf("option -i with value `%s'\n", optarg);
			config_device = strdup(optarg);
			break;

		case 'h':
			fprintf(stderr,
"Usage: ear OPTIONS [ filter expression ]\n"
"  -f, --offset=INT         flow offset threshold\n"
"  -p, --period=INT         period threshold\n"
"  -s, --select-mask=HEX    select mask\n"
"  -t, --targets=INT        targets threshold\n"
"  -l, --length=INT         substring length\n"
"  --skip-nul               skip strings with ASCII nul characters\n"
"  -n, --home-net=NET       network under protection\n"
"  -r file                  read packets from file\n"
"  -i interface             capture packets from interface\n"
"  --disable-ear            disable the EAR detection heuristic\n"
"  --enable-stride          enable the STRIDE detection heuristic\n"
"  --stride-flow-depth=INT  how deep within flows to apply STRIDE\n"
"  --stride-sled-length=INT sled length parameter for STRIDE\n"
"  -h, --help               display this help message\n");
			exit(0);

			break;

		case '?':
			/* getopt_long already printed an error message. */
			break;

		default:
			abort();
		}
	}


/* Print any remaining command line arguments (not options). */
	if (optind < argc) {
		while (optind < argc) {
			char *new_arg = argv[optind++];
			int old_len = config_bpf ? strlen(config_bpf) : 0;
			int new_len = old_len + strlen(new_arg);

			if (old_len != 0)
				new_len += 1;

			config_bpf = realloc(config_bpf, new_len);

			if (old_len != 0)
				strcat(config_bpf, " ");

			strcat(config_bpf, new_arg);
		}
		printf("expression:%s\n", config_bpf);
	}
}
