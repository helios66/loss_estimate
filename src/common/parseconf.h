#ifndef __PARSECONF_H
#define __PARSECONF_H

typedef struct conf_parameter {
  char* name;
  char* value;
  struct conf_parameter *next;
} conf_parameter_t;

typedef struct conf_category_entry {
  conf_parameter_t *params;
  struct conf_category_entry *next;
} conf_category_entry_t;

typedef struct conf_category {
  char* name;
  conf_category_entry_t *entry;
  struct conf_category *next;
} conf_category_t;

extern conf_category_t * pc_load(const char* filelist);
extern char * pc_get_param(conf_category_entry_t *entry, const char* name);
extern conf_category_entry_t * pc_get_category(conf_category_t *conf, const char *cat);
extern int pc_close(conf_category_t *conf);
#endif
