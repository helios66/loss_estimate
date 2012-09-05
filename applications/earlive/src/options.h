#ifndef OPTIONS_H
#define OPTIONS_H

extern int config_target_threshold;
extern int config_flow_limit;
extern int config_cache_size;
extern int config_substring_length;
extern int config_skip_nul;
extern u_int32_t config_select_mask;
extern char *config_trace;
extern char *config_device;
extern char *config_bpf;
extern char *config_homenet;

extern int config_ear_enabled;
extern int config_stride_enabled;
extern int config_stride_flow_depth;
extern int config_stride_sled_length;

void get_options(int argc, char **argv);

#endif
