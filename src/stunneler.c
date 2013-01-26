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
		exit(EXIT_FAILURE);
	}

	if ((conf_f = fopen(conf_path, "r")) == NULL) {
		fprintf(stderr, "Cannot open config file from %s.\n", STUNEL_CONFIG);
		exit(EXIT_FAILURE);
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
	ssh_session my_ssh_session;
	int verbosity = SSH_LOG_PROTOCOL;
	int port = 22, rc;

	json = NULL;

	if ((my_ssh_session  = ssh_new()) == NULL) {
		fprintf(stderr, "Creating new ssh_session failed.\n");
		exit(EXIT_FAILURE);
	}

	ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "localhost");
	ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);

	rc = ssh_connect(my_ssh_session);
  	if (rc != SSH_OK)
	{
		fprintf(stderr, "Error connecting to localhost: %s\n",
	            ssh_get_error(my_ssh_session));
		exit(EXIT_FAILURE);
	}

	ssh_disconnect(my_ssh_session);
	ssh_free(my_ssh_session);

	return 0;
}

int
main(int argc, char **argv)
{
	int ch;
	char conf_path[MAXPATHLEN];

	(void)strncpy(conf_path, STUNEL_CONFIG, MAXPATHLEN-1);

	/* Parse command line args */
	while ((ch = getopt(argc, argv, "hf:")) != -1) {
		switch (ch) {
			case 'f':
				memset(conf_path, 0, MAXPATHLEN);
				(void)strncpy(conf_path, optarg, MAXPATHLEN-1);
				conf_path[MAXPATHLEN - 1]='\0';
				break;
			case '?':
			case 'h':
			default:
				usage();
		}
	}
	argc -= optind;
	argv += optind;

	conf_json = get_conf_file(conf_path);

	printf("Config file: \n%s\n", cJSON_Print(conf_json));

	printf("Connecting with libssh\n");
	rem_ssh_connect(conf_json);

	return 0;
}
