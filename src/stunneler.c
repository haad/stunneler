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

#include "stunneler.h"

static void usage(void);

/*
  * Auto Tunneler forwarding local ports to remote server.
  */

static void
usage(void)
{
	printf("stunneler command to persitently call home and open tunnels to local port 22.\n");
	printf("stunneler [-f conf_file], [-p port] [-u user] [-i private key] [-d dest ip] ");
	printf("-D[for debug logging] -v [for verbose logging] -q [for quite (default)]\n");
	printf("-A[Use SSH_AGENT for public keys]");
	printf("If both -f and other options are specified at once -f is ignored.");
	exit(EXIT_SUCCESS);
}

int
main(int argc, char **argv)
{
	int ch;
	char conf_path[MAXPATHLEN];
	int conf=0;
	st_cn_t conn;

	conn = st_connection_alloc();

	conn->st_config = conf_create_with_defaults();

	(void)strncpy(conf_path, STUNEL_CONFIG, MAXPATHLEN-1);

	/* Parse command line args */
	/* TODO: Add options for port, destination ip, key and user so using conf file is not necessary*/
	while ((ch = getopt(argc, argv, "hqvDAf:p:d:i:u:")) != -1) {
		switch (ch) {
			case 'A':
				conf_set_authtype(conn->st_config, STUNEL_AUTH_AGENT);
				break;
			case 'f':
				if (argc == 3) {
					memset(conf_path, 0, MAXPATHLEN);
					(void)strncpy(conf_path, optarg, MAXPATHLEN-1);
					conf_path[MAXPATHLEN - 1]='\0';
					conf=1;
				}
				break;
			case 'p':
				conf_set_port(conn->st_config, atoi(optarg));
				break;
			case 'd':
				conf_set_address(conn->st_config, optarg);
				break;
			case 'i':
				conf_set_sshkey(conn->st_config, optarg);
				break;
			case 'u':
				conf_set_login(conn->st_config, optarg);
				break;
			case 'q':
				conf_set_log_level(conn->st_config, STUNEL_NORMAL);
				break;
			case 'v':
				conf_set_log_level(conn->st_config, STUNEL_VERBOSE);
				break;
			case 'D':
				conf_set_log_level(conn->st_config, STUNEL_DEBUG);
				break;
			case '?':
			case 'h':
			default:
				usage();
		}
	}
	argc -= optind;
	argv += optind;

	if ( conf ) {
		printf("Reading configuration from file: %s\n", conf_path);
		conf_destroy(conn->st_config);
		conn->st_config = conf_get_file(conf_path);
	}
	printf("Config file: \n%s\n", conf_dump(conn->st_config));

	if (conf_check(conn->st_config)) {
		st_connection_destroy(conn);
		exit(1);
	}

	printf("User is set to %s, port to %d\n",  conf_get_login(conn->st_config),
		conf_get_port(conn->st_config));

	printf("Connecting with libssh\n");
	st_ssh_connect(conn);

	st_connection_destroy(conn);
	return 0;
}
