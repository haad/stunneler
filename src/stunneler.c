#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <libssh/libssh.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cJSON.h"

#define STUNEL_CONFIG "stuneler.conf"

static size_t get_conf_file_size(char *path);
static void usage(void);
static cJSON * get_conf_file(char *);
static int rem_ssh_connect(cJSON *);

cJSON *conf_json;

static void
usage(void)
{
	printf("stunneler command to persitently call home and open tunnels to local port 22.\n");
	printf("stunneler [-f conf_file], [-p port] [-u user] [-i private key] [-d dest ip] \n");
	printf("If both -f and other options are specified at once -f is ignored.");
	exit(EXIT_SUCCESS);
}

static size_t
get_conf_file_size(char *path)
{
	int fd;
	struct stat sb;

	if ((fd = open(path, O_RDONLY)) < 0) {
		fprintf(stderr, "Cannot open config file from %s.\n", path);
		exit(EXIT_FAILURE);
	}

	if ( fstat(fd, &sb) != 0 ) {
		fprintf(stderr, "Could not fstat a opened file.\n");
		exit(EXIT_FAILURE);
	}

	close(fd);

	return (size_t)sb.st_size;
}

static cJSON *
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

static int
rem_ssh_connect(cJSON *json)
{
	ssh_session rem_ssh_session;
	int verbosity = SSH_LOG_PROTOCOL;
	int port, rc;

	port = cJSON_GetObjectItem(json, "rem_port")->valueint;

	if ((rem_ssh_session  = ssh_new()) == NULL) {
		fprintf(stderr, "Creating new ssh_session failed.\n");
		exit(EXIT_FAILURE);
	}
	ssh_options_set(rem_ssh_session, SSH_OPTIONS_USER, cJSON_GetObjectItem(json, "rem_login")->valuestring);
	ssh_options_set(rem_ssh_session, SSH_OPTIONS_HOST, cJSON_GetObjectItem(json, "rem_address")->valuestring);
	ssh_options_set(rem_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	ssh_options_set(rem_ssh_session, SSH_OPTIONS_PORT, &port);

	//ssh_pki_import_privkey_file(cJSON_GetObjectItem(json, "rem_ssh_key")->valuestring, NULL, NULL, NULL,priv_key);

	//
  	rc = ssh_connect(rem_ssh_session);
  	if (rc != SSH_OK)
	{
		fprintf(stderr, "Error connecting to %s : %s\n", cJSON_GetObjectItem(json, "rem_address")->valuestring,
			ssh_get_error(rem_ssh_session));
		exit(EXIT_FAILURE);
	}

	rc = ssh_userauth_privatekey_file(rem_ssh_session, cJSON_GetObjectItem(json, "rem_login")->valuestring, cJSON_GetObjectItem(json, "rem_ssh_key")->valuestring, NULL);
	if (rc != SSH_AUTH_SUCCESS)
	{
		fprintf(stderr, "Error connecting to %s : %s\n", cJSON_GetObjectItem(json, "rem_address")->valuestring,
			ssh_get_error(rem_ssh_session));
		exit(EXIT_FAILURE);
	}
  //	rc = ssh_userauth_password(rem_ssh_session,"haad", "imation");


	ssh_disconnect(rem_ssh_session);
	ssh_free(rem_ssh_session);

	return 0;
}

int
main(int argc, char **argv)
{
	int ch;
	char conf_path[MAXPATHLEN];
	int cf_flag;
	cJSON *root = cJSON_CreateObject();

	(void)strncpy(conf_path, STUNEL_CONFIG, MAXPATHLEN-1);

	/* Parse command line args */
	/* TODO: Add options for port, destination ip, key and user so using conf file is not necessary*/
	while ((ch = getopt(argc, argv, "hf:p:d:i:u:")) != -1) {
		switch (ch) {
			case 'f':
				memset(conf_path, 0, MAXPATHLEN);
				(void)strncpy(conf_path, optarg, MAXPATHLEN-1);
				conf_path[MAXPATHLEN - 1]='\0';
				cf_flag=1;
				break;
			case 'p':
				cJSON_AddItemToObject(root, "rem_port",cJSON_CreateNumber(atoi(optarg)));
				cf_flag=0;
				break;
			case 'd':
				cJSON_AddItemToObject(root, "rem_address",cJSON_CreateString(optarg));
				cf_flag=0;
				break;
			case 'i':
				cJSON_AddItemToObject(root, "rem_ssh_key",cJSON_CreateString(optarg));
				cf_flag=0;
				break;
			case 'u':
				cJSON_AddItemToObject(root, "rem_login",cJSON_CreateString(optarg));
				cf_flag=0;
				break;
			case '?':
			case 'h':
			default:
				usage();
		}
	}
	argc -= optind;
	argv += optind;

	if ( cf_flag != 0) {
		conf_json = get_conf_file(conf_path);
	} else {
		conf_json = root;
	}

	printf("Config file: \n%s\n", cJSON_Print(conf_json));

	printf("User is set to %s, port to %d\n",  cJSON_GetObjectItem(conf_json, "rem_login")->valuestring,
		cJSON_GetObjectItem(conf_json, "rem_port")->valueint);

	printf("Connecting with libssh\n");
	rem_ssh_connect(conf_json);

	return 0;
}
