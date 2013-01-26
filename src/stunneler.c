#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cJSON.h"

#define STUNEL_CONFIG "stuneler.conf"

size_t get_conf_file_size(int);

size_t
get_conf_file_size(int conf_fd)
{
	struct stat sb;

	if ( fstat(conf_fd, &sb) != 0 ) {
		fprintf(stderr, "Could not fstat a opened file.\n");
		exit(EXIT_FAILURE);
	}

	return (size_t)sb.st_size;
}


int main(int argc, char **argv)
{
	int conf_fd;

	if ((conf_fd = open(STUNEL_CONFIG, O_RDONLY)) < 0) {
		fprintf(stderr, "Cannot open config file from %s.\n", STUNEL_CONFIG);
		exit(EXIT_FAILURE);
	}

	printf("Opening config file at %s.\n", STUNEL_CONFIG);

	close(conf_fd);
	return 0;
}
