#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cJSON.h"
#include "stunneler.h"

static size_t get_conf_file_size(char *path);

static size_t
get_conf_file_size(char *path)
{
  int fd;
  struct stat sb;

  if ((fd = open(path, O_RDONLY)) < 0) {
    fprintf(stderr, "Cannot open config file from %s.\n", path);
    exit(EXIT_FAILURE);
  }

  if (fstat(fd, &sb) != 0) {
    fprintf(stderr, "Could not fstat a opened file.\n");
    exit(EXIT_FAILURE);
  }

  close(fd);

  return (size_t)sb.st_size;
}

cJSON *
get_conf_file(char *conf_path)
{
  FILE *conf_f;
  cJSON *json;

  char *mmap_file;
  size_t conf_size;

  printf("Opening config file at %s.\n", conf_path);
  conf_size = get_conf_file_size(conf_path);

  if ((mmap_file = malloc(conf_size * sizeof(char))) == NULL) {
    fprintf(stderr, "Cannot allocate memory for conf_file\n");
    return NULL;
  }

  if ((conf_f = fopen(conf_path, "r")) == NULL) {
    fprintf(stderr, "Cannot open config file from %s.\n", STUNEL_CONFIG);
    return NULL;
  }

  fread(mmap_file, 1, conf_size, conf_f);

  json = cJSON_Parse(mmap_file);

  free(mmap_file);
  fclose(conf_f);

  return json;
}

cJSON *
conf_create(void)
{

  return cJSON_CreateObject();
}

char *
conf_get_login(cJSON *json)
{

  return cJSON_GetObjectItem(json, "rem_login")->valuestring;
}

char *
conf_get_address(cJSON *json)
{

  return cJSON_GetObjectItem(json, "rem_address")->valuestring;
}

char *
conf_get_sshkey(cJSON *json)
{

  return cJSON_GetObjectItem(json, "rem_ssh_key")->valuestring;
}

int
conf_get_log_level(cJSON *json)
{

  return cJSON_GetObjectItem(json, "rem_log_level")->valueint;
}

int
conf_get_port(cJSON *json)
{

  return cJSON_GetObjectItem(json, "rem_port")->valueint;
}

void
conf_set_login(cJSON *json, char *login)
{

  cJSON_AddItemToObject(json, "rem_login", cJSON_CreateString(login));
}

void
conf_set_address(cJSON *json, char *address)
{

  cJSON_AddItemToObject(json, "rem_address", cJSON_CreateString(address));
}

void
conf_set_sshkey(cJSON *json, char *sshkey)
{

  cJSON_AddItemToObject(json, "rem_ssh_key", cJSON_CreateString(sshkey));
}

void
conf_set_port(cJSON *json, int port)
{

   cJSON_AddItemToObject(json, "rem_port", cJSON_CreateNumber(port));
}

void
conf_set_log_level(cJSON *json, int level)
{

  if (cJSON_GetObjectItem(json, "rem_log_level") == NULL ) {
    cJSON_AddItemToObject(json, "rem_log_level", cJSON_CreateNumber(level));
  } else {
    cJSON_ReplaceItemInObject(json, "rem_log_level", cJSON_CreateNumber(level));
  }
}

char *
conf_dump(cJSON *json)
{

  return cJSON_Print(json);
}
