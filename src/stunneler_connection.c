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

static int st_ssh_file_pubauth(st_config_t, ssh_session);
static int st_ssh_agent_pubauth(st_config_t, ssh_session);
static void st_setup_connection(st_cn_t);

st_cn_t
st_connection_alloc()
{
	st_cn_t conn;

	if ((conn = malloc(sizeof(struct stunel_connection))) == NULL) {
		printf("Can't allocate memory for connection. \n");
		exit(1);
	}
	memset(conn, '\0', sizeof(struct stunel_connection));

	if ((conn->st_ssh_opts = malloc(sizeof(struct stunel_ssh_opts))) == NULL) {
		printf("Can't allocate memory for ssh opts. \n");
		exit(1);
	}
	memset(conn->st_ssh_opts, '\0', sizeof(struct stunel_ssh_opts));

	return conn;
}

void
st_connection_destroy(st_cn_t conn)
{

	if (ssh_channel_is_open(conn->st_ssh_channel))
		ssh_channel_close(conn->st_ssh_channel);

	ssh_channel_free(conn->st_ssh_channel);

	if (ssh_is_connected(conn->st_ssh_session))
		ssh_disconnect(conn->st_ssh_session);

	ssh_free(conn->st_ssh_session);

	free(conn->st_ssh_opts);
	free(conn);
}

static int
st_ssh_agent_pubauth(st_config_t conf, ssh_session session)
{
	int rc;

	//rc = ssh_userauth_password(session, NULL, "imation");

	rc = ssh_userauth_autopubkey(session, NULL);
	if (rc != SSH_AUTH_SUCCESS)
	{
		fprintf(stderr, "Error userauth_privatekey_file to %s : %s, rc = %d\n", conf_get_address(conf), ssh_get_error(session), rc);
		exit(EXIT_FAILURE);
	}

	printf("Succesfully connected to server %s\n", conf_get_address(conf));
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
st_ssh_file_pubauth(st_config_t conf, ssh_session session)
{
	ssh_key priv_key;
	ssh_key pub_key;
	int rc;

	priv_key = ssh_key_new();
	pub_key = ssh_key_new();

	rc = ssh_pki_import_privkey_file(conf_get_sshkey(conf), NULL, NULL, NULL, &priv_key);
	if (rc != SSH_OK)
	{
		fprintf(stderr, "Error ssh_pki_import_privkey_file from %s, error = %d, rc = %d\n", conf_get_sshkey(conf),
			ssh_get_error_code(session), rc);
		exit(EXIT_FAILURE);
	}

	rc = ssh_pki_export_privkey_to_pubkey(priv_key, &pub_key);
	if (rc != SSH_OK)
	{
		fprintf(stderr, "Error ssh_pki_export_privkey_to_pubkey to %s, error = %s, rc = %d\n", conf_get_sshkey(conf),
			ssh_get_error(session), rc);

		ssh_key_free(priv_key);
		exit(EXIT_FAILURE);
	}

	rc = ssh_userauth_try_publickey(session, NULL, pub_key);
	if (rc != SSH_AUTH_SUCCESS)
	{
		fprintf(stderr, "Error ssh_userauth_try_publickey to %s, error = %s, rc = %d\n", conf_get_sshkey(conf),
			ssh_get_error(session), rc);

		ssh_key_free(priv_key);
		ssh_key_free(pub_key);
		exit(EXIT_FAILURE);
	}

	/* Try to authenticate with keys. */
	rc = ssh_userauth_publickey(session, NULL, priv_key);
	if (rc != SSH_AUTH_SUCCESS)
	{
		fprintf(stderr, "Error ssh_userauth_publickey to %s : %s, rc = %d\n", conf_get_address(conf), ssh_get_error(session), rc);
		exit(EXIT_FAILURE);
	}

	if (priv_key)
		ssh_key_free(priv_key);

	if (pub_key)
		ssh_key_free(pub_key);

	return 0;
}

static int
st_ssh_pass_auth(st_config_t conf, ssh_session session) {
	int rc;

	rc = ssh_userauth_password(session, NULL, "imation");
	if (rc != SSH_AUTH_SUCCESS)
	{
		fprintf(stderr, "Error userauth_privatekey_file to %s : %s, rc = %d\n", conf_get_address(conf), ssh_get_error(session), rc);
		exit(EXIT_FAILURE);
	}

	printf("Succesfully connected to server %s\n", conf_get_address(conf));
	return 0;
}

static int
st_auth_connection(st_cn_t conn)
{
	st_config_t conf = conn->st_config;

	switch(conf_get_authtype(conf)) {
		case STUNEL_AUTH_AGENT:
			st_ssh_agent_pubauth(conf, conn->st_ssh_session);
			break;
		case STUNEL_AUTH_PUBLIC:
			st_ssh_file_pubauth(conf, conn->st_ssh_session);
			break;
		case STUNEL_AUTH_PASSW:
			st_ssh_pass_auth(conf, conn->st_ssh_session);
			break;
		default:
			break;
	}

	return 0;
}

static void
st_setup_connection(st_cn_t conn)
{
	st_config_t conf = conn->st_config;
	int verbosity = conf_get_log_level(conf);
	int port, comp_level;

	if ((conn->st_ssh_session  = ssh_new()) == NULL) {
		fprintf(stderr, "Creating new ssh_session failed.\n");
		exit(EXIT_FAILURE);
	}

	port = conf_get_port(conf);
	comp_level = conf_get_compression_level(conf);

	ssh_options_set(conn->st_ssh_session, SSH_OPTIONS_USER, conf_get_login(conf));
	ssh_options_set(conn->st_ssh_session, SSH_OPTIONS_HOST, conf_get_address(conf));
	ssh_options_set(conn->st_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	ssh_options_set(conn->st_ssh_session, SSH_OPTIONS_PORT, &port);
	ssh_options_set(conn->st_ssh_session, SSH_OPTIONS_HOSTKEYS, conf_get_ssh_hostkey(conf));
	ssh_options_set(conn->st_ssh_session, SSH_OPTIONS_COMPRESSION, conf_get_compression(conf));
	ssh_options_set(conn->st_ssh_session, SSH_OPTIONS_COMPRESSION_LEVEL, &comp_level);

}

int
st_ssh_connect(st_cn_t conn)
{
	st_config_t conf = conn->st_config;
	int nbytes;
	char *banner;
	char buffer[256];

	st_setup_connection(conn);

	if(ssh_connect(conn->st_ssh_session) != SSH_OK) {
		fprintf(stderr, "Error connecting to %s : %s\n", conf_get_address(conf), ssh_get_error(conn->st_ssh_session));
		exit(EXIT_FAILURE);
	}

	printf("Trying to verify server RSA key in knownhosts file.\n");
	if(verify_knownhost(conn->st_ssh_session) < 0) {
		st_connection_destroy(conn);
		return -1;
	}

	/* Try to authenticate agains server with choosen method */
	printf("Trying to connect to server\n");
	st_auth_connection(conn);

	banner=ssh_get_issue_banner(conn->st_ssh_session);
	if (banner) {
		printf("%s\n", banner);
		free(banner);
	}

	conn->st_ssh_channel = ssh_channel_new(conn->st_ssh_session);
	ssh_channel_open_session(conn->st_ssh_channel );
	ssh_channel_request_exec(conn->st_ssh_channel , "ls -la");

	nbytes = ssh_channel_read(conn->st_ssh_channel , buffer, sizeof(buffer), 0);
	while (nbytes > 0) {
		if (fwrite(buffer, 1, nbytes, stdout) != (unsigned int) nbytes) {
			printf("ASDASDASD\n");
		}
		nbytes = ssh_channel_read(conn->st_ssh_channel , buffer, sizeof(buffer), 0);
	}

	return 0;
}
