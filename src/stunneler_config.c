/*-
 * Copyright (c) 2008 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Adam Hamsik.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

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

  printf("Config file size is %zd \n", (size_t)sb.st_size);
  return (size_t)sb.st_size;
}

st_config_t
conf_get_file(char *conf_path)
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

  return (st_config_t )json;
}

st_config_t
conf_create_with_defaults(void)
{
  cJSON *root;

  root = cJSON_CreateObject();

  if (root == NULL) {
    printf("Can't create new conf root\n.");
    return NULL;
  }

  /* By default we set log level to NORMAL */
  conf_set_log_level(root, STUNEL_NORMAL);

  /* By default we use public key auth */
  conf_set_authtype(root, STUNEL_AUTH_PUBLIC);

  /* Set default hostkey algorithms */
  conf_set_ssh_hostkey(root, STUNEL_HOSTKEY_ALG);

  /* set compression algorithm and level */
  conf_set_compression(root, STUNEL_COMP_ALG);
  conf_set_compression(root, STUNEL_COMP_LVL);

  return (st_config_t )root;
}

char *
conf_get_login(st_config_t json)
{

  return cJSON_GetItemString(json, "rem_login");
}

char *
conf_get_address(st_config_t json)
{

  return cJSON_GetItemString(json, "rem_address");
}

char *
conf_get_sshkey(st_config_t json)
{

  return cJSON_GetItemString(json, "rem_ssh_key");
}

char *
conf_get_ssh_hostkey(st_config_t json)
{

  return cJSON_GetItemString(json, "rem_ssh_hostkey");
}

char *
conf_get_compression(st_config_t json)
{

  return cJSON_GetItemString(json, "rem_ssh_compression");
}

int
conf_get_compression_level(st_config_t json)
{

  return cJSON_GetItemNumber(json, "rem_ssh_compression_level");
}

int
conf_get_authtype(st_config_t json)
{

  return cJSON_GetItemNumber(json, "rem_authtype");
}

int
conf_get_log_level(st_config_t json)
{

  return cJSON_GetItemNumber(json, "rem_log_level");
}

int
conf_get_port(st_config_t json)
{

  return cJSON_GetItemNumber(json, "rem_port");
}

void
conf_set_login(st_config_t json, char *login)
{

  cJSON_AddItemToObject(json, "rem_login", cJSON_CreateString(login));
}

void
conf_set_address(st_config_t json, char *address)
{

  cJSON_AddItemToObject(json, "rem_address", cJSON_CreateString(address));
}

void
conf_set_sshkey(st_config_t json, char *sshkey)
{

  cJSON_AddItemToObject(json, "rem_ssh_key", cJSON_CreateString(sshkey));
}

void
conf_set_ssh_hostkey(st_config_t json, char *hostkey)
{

  cJSON_AddItemToObject(json, "rem_ssh_hostkey", cJSON_CreateString(hostkey));
}

void
conf_set_compression(st_config_t json, char *comp)
{

  cJSON_AddItemToObject(json, "rem_ssh_compression", cJSON_CreateString(comp));
}

void
conf_set_compression_level(st_config_t json, int comp_level)
{

  cJSON_AddItemToObject(json, "rem_ssh_compression_level", cJSON_CreateNumber(comp_level));
}

void
conf_set_port(st_config_t json, int port)
{

   cJSON_AddItemToObject(json, "rem_port", cJSON_CreateNumber(port));
}

void
conf_set_log_level(st_config_t json, int level)
{

  if (cJSON_GetObjectItem(json, "rem_log_level") == NULL ) {
    cJSON_AddItemToObject(json, "rem_log_level", cJSON_CreateNumber(level));
  } else {
    cJSON_ReplaceItemInObject(json, "rem_log_level", cJSON_CreateNumber(level));
  }
}

void
conf_set_authtype(st_config_t json, int auth_type)
{

  if (cJSON_GetObjectItem(json, "rem_authtype") == NULL ) {
    cJSON_AddItemToObject(json, "rem_authtype", cJSON_CreateNumber(auth_type));
  } else {
    cJSON_ReplaceItemInObject(json, "rem_authtype", cJSON_CreateNumber(auth_type));
  }
}

char *
conf_dump(st_config_t json)
{

  return cJSON_Print(json);
}

void
conf_destroy(st_config_t json)
{

  cJSON_Delete(json);
}

/* Check config file if we have enough data to connect to server.*/
int
conf_check(st_config_t json)
{

  if ( conf_get_login(json) == NULL ||
    conf_get_port(json) == -1 ||
    conf_get_address(json) ==NULL ) {
    printf("Not enough data to connect to a server. Exiting !! \n");
    return 1;
  }

  return 0;
}
