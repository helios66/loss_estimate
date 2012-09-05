#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "parseconf.h"
#include "debug.h"

#define BUFSIZE 1024
#define TAGSIZE 64

/* Forward declaration. */
static conf_category_t *loadfile(const char *file);

conf_category_t *pc_load(const char* filelist) 
//Loads the first conf file located in the filelist
//Return pointer to conf struct if conf file is loaded
{
  conf_category_t *conf = NULL;
  char *p, *file;
  char buf[BUFSIZE];

  if (strlen(filelist) >= BUFSIZE)
    return 0;

  strncpy(buf, filelist, BUFSIZE);
  file = buf;
  
  //Walk through filelist
  while((p = strchr(file, ':')) != NULL && conf == NULL)
  {
    *p = '\0';
    conf = loadfile(file);
    file = p + 1;
  }
  
  if (conf == NULL)
    conf = loadfile(file);

  return conf;
}

static conf_category_t *loadfile(const char *file)
{
  conf_category_t *cp, *conf;
  conf_category_entry_t *entry, **le, *entry2;
  conf_parameter_t *param, **lp;
  FILE *f;
  int c;
  char buf[BUFSIZE], tag[TAGSIZE], val[BUFSIZE], cat[TAGSIZE];

  cat[0] = '\0';
  if((f = fopen(file, "r")) != NULL){
    conf = malloc(sizeof(conf_category_t));
    conf->name = malloc(sizeof(char));
    conf->name[0] = '\0';
    conf->entry = NULL;
    conf->next = NULL;
    le = &conf->entry;
    //Parse the file
    while (fgets(buf, BUFSIZE, f) != NULL)
    {
      if (buf[0] != ';' && buf[0] != '#')
      {
        //a-zA-Z /0-9:.
        if ((c = sscanf(buf, "%[^=]=%[^\r\n]", tag, val)) == 2)
        {
          param = malloc(sizeof(conf_parameter_t));
          param->next = NULL;
          param->name = strdup(tag);
          param->value = strdup(val);
          if (*le == NULL)
          {
            *le = malloc(sizeof(conf_category_entry_t));
            (*le)->params = NULL;
            (*le)->next = NULL;
            lp = &(*le)->params;
          }
          *lp = param;
          lp = &param->next;
          
        }
        else if ((c = sscanf(buf, "[%[^]]", cat)) == 1)
        {
          entry = pc_get_category(conf, cat);
          
          if (entry == NULL)
          {
            //Create new main category
            cp = malloc(sizeof(conf_category_t));
            cp->next = conf;
            cp->name = strdup(cat);
            cp->entry = NULL;
            conf = cp;
            le = &conf->entry;
          }
          else
          {
            //Find last category of this type
            entry2 = malloc(sizeof(conf_category_entry_t));
            entry2->params = NULL;
            entry2->next = NULL;
            lp = &entry2->params;
            le = &entry2;
            while (entry->next != NULL)
              entry = entry->next;
            entry->next = entry2;
            
          }
        }
      }
    }

    fclose(f);
    return conf;
  }
  else
    return NULL;
}

conf_category_entry_t *pc_get_category(conf_category_t *conf, const char *cat) 
{
  conf_category_t *cp = conf;

  while (cp != NULL)
  {
    if (strcmp(cp->name, cat) == 0)
      return cp->entry;
    else
      cp = cp->next;
  }
  return NULL;
}

char *pc_get_param(conf_category_entry_t *entry, const char *name)
{
  conf_parameter_t *p;

  if (entry == NULL)
  {
      DEBUG_CMD(Debug_Message("pc_get_param: NULL category"));
      exit(1);
  }
  p = entry->params;
  while (p != NULL)
  {
    if (strcmp(p->name, name) == 0)
      return p->value;
    else
      p = p->next;
  }
  return NULL;
}

int pc_close(conf_category_t *conf) 
{
  conf_category_t *c, *c2;
  conf_category_entry_t *e, *e2;
  conf_parameter_t *p, *p2;

  c = conf;
  while (c != NULL)
  {
    e = c->entry;
    while (e != NULL)
    {
      p = e->params;
      while (p)
      {
        free(p->name);
        free(p->value);
        p2 = p;
        p = p->next;
        free(p2);
      }
      e2 = e;
      e = e->next;
      free(e2);
    }
    free(c->name);
    c2 = c;
    c = c->next;
    free(c2);
  }
  return 1;
}
