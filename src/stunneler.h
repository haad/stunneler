#ifndef STUNNELER_H
#define STUNNELER_H

#include "cJSON.h"
#include <libssh/libssh.h>

#define STUNEL_CONFIG "stuneler.conf"

#define STUNEL_NORMAL SSH_LOG_RARE
#define STUNEL_VERBOSE SSH_LOG_PROTOCOL
#define STUNEL_DEBUG SSH_LOG_PACKET

/* stunneler_config.c */
cJSON * get_conf_file(char *);
cJSON * conf_create(void);

char * conf_dump(cJSON *);

char * conf_get_login(cJSON *);
char * conf_get_address(cJSON *);
char * conf_get_sshkey(cJSON *);
int conf_get_log_level(cJSON *);
int conf_get_port(cJSON *);

void conf_set_login(cJSON *, char *);
void conf_set_address(cJSON *, char *);
void conf_set_sshkey(cJSON *, char *);
void conf_set_log_level(cJSON *, int);
void conf_set_port(cJSON *, int);

/* stunneler_sshlib.c */
int verify_knownhost(ssh_session session);

/* stunneler.c */

#endif
