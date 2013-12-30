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
#define STUNEL_AUTH_PASSW 3

#define STUNEL_HOSTKEY_ALG "ssh-rsa,ssh-dsa,ecdsa-sha2-nistp256"

#define STUNEL_COMP_ALG "zlib@openssh.com"
#define STUNEL_COMP_LVL "1"

typedef cJSON * st_config_t;

struct stunel_ssh_opts {
  ssh_session st_session;
  ssh_channel st_channel;
  ssh_key st_priv_key; /* unused */
  ssh_key st_pub_key; /* unused */
};
typedef struct stunel_ssh_opts * stunel_ssh_opts_t;

struct stunel_connection {
  st_config_t st_config;
  stunel_ssh_opts_t st_ssh_opts;
  int (*st_ssh_auth_fn) (st_config_t, ssh_session);
};
typedef struct stunel_connection * st_cn_t;

#define st_ssh_session st_ssh_opts->st_session
#define st_ssh_channel st_ssh_opts->st_channel
#define st_ssh_priv_key st_ssh_opts->st_priv_key
#define st_ssh_pub_key st_ssh_opts->st_pub_key

/* stunneler_config.c */
st_config_t conf_get_file(char *);
st_config_t conf_create_with_defaults(void);

int conf_check(st_config_t);
char * conf_dump(st_config_t);
void conf_destroy(st_config_t);

char * conf_get_login(st_config_t);
char * conf_get_pass(st_config_t);
char * conf_get_address(st_config_t);
char * conf_get_sshkey(st_config_t);
char * conf_get_ssh_hostkey(st_config_t);
char * conf_get_compression(st_config_t);
int conf_get_compression_level(st_config_t);
int conf_get_log_level(st_config_t);
int conf_get_port(st_config_t);
int conf_get_authtype(st_config_t);

void conf_set_login(st_config_t, char *);
void conf_set_address(st_config_t, char *);
void conf_set_sshkey(st_config_t, char *);
void conf_set_ssh_hostkey(st_config_t, char *);
void conf_set_compression(st_config_t, char *);
void conf_set_compression_level(st_config_t, int);
void conf_set_log_level(st_config_t, int);
void conf_set_port(st_config_t, int);
void conf_set_authtype(st_config_t, int);

/* stunneler_sshlib.c */
int verify_knownhost(ssh_session session);

/* stunneler_connection.c */
int st_ssh_connect(st_cn_t);
st_cn_t st_connection_alloc(void);
void st_connection_destroy(st_cn_t);

/* stunneler.c */

#endif
