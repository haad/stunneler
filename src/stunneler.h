#ifndef STUNNELER_H
#define STUNNELER_H

#include "cJSON.h"
#include <libssh/libssh.h>

#define STUNEL_CONFIG "stuneler.conf"

#define STUNEL_NORMAL SSH_LOG_RARE
#define STUNEL_VERBOSE SSH_LOG_PROTOCOL
#define STUNEL_DEBUG SSH_LOG_PACKET
#define STUNEL_TRACE SSH_LOG_TRACE

#define STUNEL_AUTH_PUBLIC 1
#define STUNEL_AUTH_AGENT 2

/* stunneler_config.c */
cJSON * get_conf_file(char *);
cJSON * conf_create(void);

char * conf_dump(cJSON *);

char * conf_get_login(cJSON *);
char * conf_get_address(cJSON *);
char * conf_get_sshkey(cJSON *);
char * conf_get_ssh_hostkey(cJSON *);
int conf_get_log_level(cJSON *);
int conf_get_port(cJSON *);
int conf_get_authtype(cJSON *);

void conf_set_login(cJSON *, char *);
void conf_set_address(cJSON *, char *);
void conf_set_sshkey(cJSON *, char *);
void conf_set_ssh_hostkey(cJSON *, char *);
void conf_set_log_level(cJSON *, int);
void conf_set_port(cJSON *, int);
void conf_set_authtype(cJSON *, int);

/* stunneler_sshlib.c */
int verify_knownhost(ssh_session session);

/* stunneler.c */

#endif
