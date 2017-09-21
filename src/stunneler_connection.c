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

/*
  * Allocate new connection.
  */
st_cn_t
st_connection_alloc(void)
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

/*
  * Destroys connection.
  */
void
st_connection_destroy(st_cn_t conn)
{

	if (ssh_channel_is_open(conn->st_ssh_channel))
		ssh_channel_close(conn->st_ssh_channel);

	ssh_channel_free(conn->st_ssh_channel);

	if (conn->st_ssh_priv_key)
		ssh_key_free(conn->st_ssh_priv_key);

	if (conn->st_ssh_pub_key)
		ssh_key_free(conn->st_ssh_pub_key);

	if (ssh_is_connected(conn->st_ssh_session))
		ssh_disconnect(conn->st_ssh_session);

	ssh_free(conn->st_ssh_session);

	free(conn->st_ssh_opts);
	free(conn);
}

/*
  * This is public key ssh-agent authentication routine.
  */
static int
st_ssh_agent_pubauth(st_config_t conf, ssh_session session)
{
	int rc;

	rc = ssh_userauth_autopubkey(session, NULL);
	if (rc != SSH_AUTH_SUCCESS)
	{
		fprintf(stderr, "Error ssh_userauth_autopubkey to %s : %s, rc = %d\n", conf_get_address(conf),
		 ssh_get_error(session), rc);
		return rc;
	}

	printf("Succesfully connected to server %s\n", conf_get_address(conf));
	return rc;
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

	priv_key = NULL;
	pub_key = NULL;

	/* First import private key from file */
	rc = ssh_pki_import_privkey_file(conf_get_sshkey(conf), NULL, NULL, NULL, &priv_key);
	if (rc != SSH_OK) {
		fprintf(stderr, "Error ssh_pki_import_privkey_file from %s, error = %d, rc = %d\n", conf_get_sshkey(conf),
			ssh_get_error_code(session), rc);
		goto error;
	}

	/* Export public key from private key */
	rc = ssh_pki_export_privkey_to_pubkey(priv_key, &pub_key);
	if (rc != SSH_OK) {
		fprintf(stderr, "Error ssh_pki_export_privkey_to_pubkey to %s, error = %s, rc = %d\n", conf_get_sshkey(conf),
			ssh_get_error(session), rc);
		goto error;
	}

	/* Try to authenticate with keys. */
	rc = ssh_userauth_publickey(session, NULL, priv_key);
	if (rc != SSH_AUTH_SUCCESS) {
		fprintf(stderr, "Error ssh_userauth_publickey to %s : %s, rc = %d\n", conf_get_address(conf),
			ssh_get_error(session), rc);
		goto error;
	}

error:
	if (priv_key)
		ssh_key_free(priv_key);

	if (pub_key)
		ssh_key_free(pub_key);

	return rc;
}

/*
 * Authenticate against server with password.
 *
 * TODO: This doesn't work on SSHv2 servers they need ssh_userauth_kbdint.
 */
static int
st_ssh_pass_auth(st_config_t conf, ssh_session session)
{
	int rc;

	rc = ssh_userauth_password(session, NULL, conf_get_pass(conf));
	if (rc != SSH_AUTH_SUCCESS)
	{
		fprintf(stderr, "Error ssh_userauth_password to %s : %s, rc = %d, pass = %s\n", conf_get_address(conf),
			ssh_get_error(session), rc, conf_get_pass(conf));
		return rc;
	}

	printf("Succesfully connected to server %s\n", conf_get_address(conf));
	return rc;
}

static int
st_auth_connection(st_cn_t conn)
{
	int rc;
	st_config_t conf = conn->st_config;

	switch(conf_get_authtype(conf)) {
		case STUNEL_AUTH_AGENT:
			conn->st_ssh_auth_fn=&st_ssh_agent_pubauth;
			break;
		case STUNEL_AUTH_PUBLIC:
			conn->st_ssh_auth_fn=&st_ssh_file_pubauth;
			break;
		case STUNEL_AUTH_PASSW:
			conn->st_ssh_auth_fn=&st_ssh_pass_auth;
			break;
		default:
			printf("Unknokwn AUTHTYPE = %d\n", conf_get_authtype(conf));
			rc = SSH_AUTH_ERROR;
			break;
	}

	if (conn->st_ssh_auth_fn)
		rc = conn->st_ssh_auth_fn(conf, conn->st_ssh_session);

	if (rc != SSH_AUTH_SUCCESS) {
		printf("Authentication against server failed with exit code %d\n", rc);
		st_connection_destroy(conn);
		exit(1);
	}

	return rc;
}

static void
st_setup_connection(st_cn_t conn)
{
	st_config_t conf = conn->st_config;
	int verbosity = conf_get_log_level(conf);
	int port, comp_level;

	if ((conn->st_ssh_session  = ssh_new()) == NULL) {
		fprintf(stderr, "Creating new ssh_session failed.\n");
		st_connection_destroy(conn);
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

static int
st_ssh_channel_create(st_cn_t conn)
{
	int nbytes;
	char buffer[512];

	conn->st_ssh_channel = ssh_channel_new(conn->st_ssh_session);
	ssh_channel_open_session(conn->st_ssh_channel);
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

static int
st_ssh_forward_create(st_cn_t conn)
{
	int rc;
	ssh_channel channel;
	char buffer[256];
	int nbytes, nwritten;

	rc = ssh_forward_listen(conn->st_ssh_session, NULL, 34567, NULL);
	if (rc != SSH_OK)
	{
		fprintf(stderr, "Error opening remote port: %s\n",
	 	ssh_get_error(conn->st_ssh_session));
	 	return rc;
	}

	channel = ssh_forward_accept(conn->st_ssh_session, 60000);
	if (channel == NULL)
	{
		fprintf(stderr, "Error waiting for incoming connection: %s\n",
		ssh_get_error(conn->st_ssh_session));
		return SSH_ERROR;
	}
	while (1)
	{
		nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
		if (nbytes < 0)
		{
			fprintf(stderr, "Error reading incoming data: %s\n",
			ssh_get_error(conn->st_ssh_session));
			ssh_channel_send_eof(channel);
			ssh_channel_free(channel);
			return SSH_ERROR;
		}
		if (strncmp(buffer, "GET /", 5)) continue;
		nbytes = strlen("ASDASDSAD");
		nwritten = ssh_channel_write(channel, "ASDASDSAD", nbytes);
		if (nwritten != nbytes)
		{
			fprintf(stderr, "Error sending answer: %s\n",
			ssh_get_error(conn->st_ssh_session));
			ssh_channel_send_eof(channel);
			ssh_channel_free(channel);
			return SSH_ERROR;
		}
	printf("Sent answer\n");
	}
	ssh_channel_send_eof(channel);
	ssh_channel_free(channel);
}

int
st_ssh_connect(st_cn_t conn)
{
	st_config_t conf = conn->st_config;

	st_setup_connection(conn);

	if (ssh_connect(conn->st_ssh_session) != SSH_OK) {
		fprintf(stderr, "Error connecting to %s : %s\n", conf_get_address(conf),
			ssh_get_error(conn->st_ssh_session));
		st_connection_destroy(conn);
		exit(EXIT_FAILURE);
	}

	printf("Trying to verify server RSA key in knownhosts file.\n");
	if (verify_knownhost(conn->st_ssh_session) < 0) {
		st_connection_destroy(conn);
		return -1;
	}

	/* Try to authenticate agains server with choosen method */
	printf("Trying to connect to server\n");
	st_auth_connection(conn);

	printf("Creating a channel\n");
	st_ssh_channel_create(conn);
	st_ssh_forward_create(conn);

	st_connection_destroy(conn);
	return 0;
}
