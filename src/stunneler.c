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
static int rem_ssh_connect(cJSON *);
static int rem_ssh_file_pubauth(cJSON *, ssh_session);
static int rem_ssh_agent_pubauth(cJSON *, ssh_session);

/*
  * Auto Tunneler forwarding local ports to remote server.
  */


cJSON *conf_json;

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

static int
rem_ssh_agent_pubauth(cJSON *json, ssh_session rem_ssh_session)
{
	int rc;

	//rc = ssh_userauth_password(rem_ssh_session, NULL, "imation");

	rc = ssh_userauth_autopubkey(rem_ssh_session, NULL);
	if (rc != SSH_AUTH_SUCCESS)
	{
		fprintf(stderr, "Error userauth_privatekey_file to %s : %s, rc = %d\n", conf_get_address(json), ssh_get_error(rem_ssh_session), rc);
		exit(EXIT_FAILURE);
	}

	printf("Succesfully connected to server %s\n", conf_get_address(json));
	return 0;
}

/*
  * This routine tries to authenticate against server with public key.
  *
  * Auth works like this:
  *
  * 1) Import private key --> ssh_pki_import_privkey_file
  * 2) Export public key from private key --> ssh_pki_export_privkey_to_pubkey
  * 3) Offer public key to server --> ssh_userauth_try_publickey
  * 4) If offer is successful try to actually authenticate against server. --> ssh_userauth_publickey
  * 5) Free keys --> ssh_key_freee
  *
  * For more info see: http://api.libssh.org/master/libssh_tutor_authentication.html
  */

static int
rem_ssh_file_pubauth(cJSON *json, ssh_session rem_ssh_session)
{
	ssh_key *priv_key;
	ssh_key *pub_key;
	int rc;

	priv_key = NULL;
	pub_key = NULL;

	rc = ssh_pki_import_privkey_file(conf_get_sshkey(json), NULL, NULL, NULL, priv_key);
	if (rc != SSH_OK)
	{
		fprintf(stderr, "Error ssh_pki_import_privkey_file from %s, error = %d, rc = %d\n", conf_get_sshkey(json),
			ssh_get_error_code(rem_ssh_session), rc);
		exit(EXIT_FAILURE);
	}

	rc = ssh_pki_export_privkey_to_pubkey(*priv_key, pub_key);
	if (rc != SSH_OK)
	{
		fprintf(stderr, "Error ssh_pki_export_privkey_to_pubkey to %s, error = %s, rc = %d\n", conf_get_sshkey(json),
			ssh_get_error(rem_ssh_session), rc);

		ssh_key_free(*priv_key);
		exit(EXIT_FAILURE);
	}

	rc = ssh_userauth_try_publickey(rem_ssh_session, NULL, *pub_key);
	if (rc != SSH_AUTH_SUCCESS)
	{
		fprintf(stderr, "Error ssh_pki_export_privkey_to_pubkey to %s, error = %s, rc = %d\n", conf_get_sshkey(json),
			ssh_get_error(rem_ssh_session), rc);

		ssh_key_free(*priv_key);
		ssh_key_free(*pub_key);
		exit(EXIT_FAILURE);
	}

	rc = ssh_userauth_publickey(rem_ssh_session, NULL, *priv_key);
	if (rc != SSH_AUTH_SUCCESS)
	{
		fprintf(stderr, "Error userauth_privatekey_file to %s : %s, rc = %d\n", conf_get_address(json), ssh_get_error(rem_ssh_session), rc);
		exit(EXIT_FAILURE);
	}

	if (priv_key)
		ssh_key_free(*priv_key);

	if (pub_key)
		ssh_key_free(*pub_key);

	return 0;
}

static int
rem_ssh_connect(cJSON *json)
{
	ssh_session rem_ssh_session;
	int verbosity = conf_get_log_level(json);
	int port;
	char *banner;

	if ((rem_ssh_session  = ssh_new()) == NULL) {
		fprintf(stderr, "Creating new ssh_session failed.\n");
		exit(EXIT_FAILURE);
	}

	port = conf_get_port(json);

	ssh_options_set(rem_ssh_session, SSH_OPTIONS_USER, conf_get_login(json));
	ssh_options_set(rem_ssh_session, SSH_OPTIONS_HOST, conf_get_address(json));
	ssh_options_set(rem_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	ssh_options_set(rem_ssh_session, SSH_OPTIONS_PORT, &port);

	if(ssh_connect(rem_ssh_session) != SSH_OK) {
		fprintf(stderr, "Error connecting to %s : %s\n", conf_get_address(json), ssh_get_error(rem_ssh_session));
		exit(EXIT_FAILURE);
	}

  	/*rc = ssh_connect(rem_ssh_session);
  	if (rc != SSH_OK)
	{
		fprintf(stderr, "Error connecting to %s : %s\n", conf_get_address(json), ssh_get_error(rem_ssh_session));
		exit(EXIT_FAILURE);
	}*/

	printf("Trying to verify server RSA key in knownhosts file.\n");
	if( verify_knownhost(rem_ssh_session) < 0 ){
 		ssh_disconnect(rem_ssh_session);
		return 0;
  	}

	printf("Trying to connect to server\n");
	if (conf_get_authtype(json) == STUNEL_AUTH_AGENT)
		rem_ssh_agent_pubauth(json, rem_ssh_session);
	else
		rem_ssh_file_pubauth(json, rem_ssh_session);

	banner=ssh_get_issue_banner(rem_ssh_session);
 	if(banner) {
		printf("%s\n",banner);
		free(banner);
	}

	if(ssh_is_connected(rem_ssh_session))
		ssh_disconnect(rem_ssh_session);

	ssh_free(rem_ssh_session);

	return 0;
}

int
main(int argc, char **argv)
{
	int ch;
	char conf_path[MAXPATHLEN];
	int conf=0;
	cJSON *root = conf_create();

	(void)strncpy(conf_path, STUNEL_CONFIG, MAXPATHLEN-1);

	/* By default we set log level to NORMAL */
	conf_set_log_level(root, STUNEL_NORMAL);

	/* By default we use public key auth */
	conf_set_authtype(root, STUNEL_AUTH_PUBLIC);

	/* Parse command line args */
	/* TODO: Add options for port, destination ip, key and user so using conf file is not necessary*/
	while ((ch = getopt(argc, argv, "hqvDAf:p:d:i:u:")) != -1) {
		switch (ch) {
			case 'A':
				conf_set_authtype(root, STUNEL_AUTH_AGENT);
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
				conf_set_port(root, atoi(optarg));
				break;
			case 'd':
				conf_set_address(root, optarg);
				break;
			case 'i':
				conf_set_sshkey(root, optarg);
				break;
			case 'u':
				conf_set_login(root, optarg);
				break;
			case 'q':
				conf_set_log_level(root, STUNEL_NORMAL);
				break;
			case 'v':
				conf_set_log_level(root, STUNEL_VERBOSE);
				break;
			case 'D':
				conf_set_log_level(root, STUNEL_DEBUG);
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
		conf_json = get_conf_file(conf_path);
	} else {
		conf_json = root;
	}

	printf("Config file: \n%s\n", conf_dump(conf_json));

	printf("User is set to %s, port to %d\n",  conf_get_login(conf_json),
		conf_get_port(conf_json));

	printf("Connecting with libssh\n");
	rem_ssh_connect(conf_json);

	return 0;
}
