/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-rpc-tls-psk.c - TLS-PSK functionality to protect communication

   Copyright (C) 2013, NORDUnet A/S

   pkcs11-proxy is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   pkcs11-proxy is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Fredrik Thulin <fredrik@thulin.net>
*/

#include "config.h"

#include "gck-rpc-private.h"
#include "gck-rpc-tls-psk.h"

#include <sys/param.h>
#include <assert.h>

/* for file I/O */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

/* TLS pre-shared key */
static char tls_psk_identity[1024] = { 0, };
static char tls_psk_key_filename[MAXPATHLEN] = { 0, };

/* -----------------------------------------------------------------------------
 * LOGGING and DEBUGGING
 */
#ifndef DEBUG_OUTPUT
#define DEBUG_OUTPUT 0
#endif
#if DEBUG_OUTPUT
#define debug(x) gck_rpc_debug x
#else
#define debug(x)
#endif
#define warning(x) gck_rpc_warn x


/* -----------------------------------------------------------------------------
 * TLS-PSK (pre-shared key) functionality
 */

/* Utility function to decode a single hex char.
 *
 * Returns value as integer, or -1 on invalid hex char (not 0-9, a-f or A-F).
 */
static int
_tls_psk_to_hex(char val)
{
	if (val >= '0' && val <= '9')
		return val - '0';
	if (val >= 'a' && val <= 'f')
		return val - 'a' + 10;
	if (val >= 'A' && val <= 'F')
		return val - 'A' + 10;
	return -1;
}

/* Hex decode the key from an entry in the TLS-PSK key file. Entrys are of the form
 *
 *   identity:hex-key\n
 *
 * Logging debug/error messages here is a bit problematic since the key is sensitive
 * and should not be logged to syslog for example. This code avoids logging the key
 * part and only logs identity.
 *
 * Returns 0 on failure, number of bytes in hex-decoded key on success.
 */
static int
_tls_psk_decode_key(const char *identity, const char *hexkey, unsigned char *psk, unsigned int max_psk_len)
{
	int psk_len, i;

	/* check that length of the key is even */
	if ((strlen(hexkey) % 2) != 0) {
		warning(("un-even length TLS-PSK key"));
		return 0;
	}

	memset(psk, 0, max_psk_len);
	psk_len = 0;

	while (*hexkey && (psk_len < max_psk_len)) {
		/* decode first half of byte, check for errors */
		if ((i = _tls_psk_to_hex(*hexkey)) < 0) {
			warning(("bad TLS-PSK '%.100s' hex char at position %i (%c)",
				 identity, psk_len + 1, *hexkey));
			return 0;
		}
		*psk = i << 4;
		hexkey++;

		/* decode second half of byte, check for errors */
		if ((i = _tls_psk_to_hex(*hexkey)) < 0) {
		        warning(("bad TLS-PSK '%.100s' hex char at position %i (%c)",
				 identity, psk_len + 1, *hexkey));
			return 0;
		}
		*psk |= i;
		hexkey++;

		psk_len++;
		psk++;
	}
	if (*hexkey) {
		warning(("too long TLS-PSK '%.100s' key (max %i)", identity, max_psk_len));
		return 0;
	}

	return psk_len;
}

/*
 * Callbacks invoked by OpenSSL PSK initialization.
 */


/* Server side TLS-PSK initialization callback. Given an identity (chosen by the client),
 * locate a pre-shared key and put it in psk.
 *
 * Returns the number of bytes put in psk, or 0 on failure.
 */
static unsigned int
_tls_psk_server_cb(SSL *ssl, const char *identity,
		   unsigned char *psk, unsigned int max_psk_len)
{
	char line[1024], *hexkey;
	unsigned int psk_len;
	int i, fd;

	debug(("Initializing TLS-PSK with keyfile '%.100s', identity '%.100s'",
	       tls_psk_key_filename, identity));

	if ((fd = open(tls_psk_key_filename, O_RDONLY | O_CLOEXEC)) < 0) {
		gck_rpc_warn("can't open TLS-PSK keyfile '%.100s' for reading : %s",
			     tls_psk_key_filename, strerror(errno));
		return 0;
	}

	/* Format of PSK file is that of GnuTLS psktool.
	 *
	 * identity:hex-key
	 * other:another-hex-key
	*/
	psk_len = 0;

	while (gck_rpc_fgets(line, sizeof(line) - 1, fd) > 0) {
		/* Find first colon and replace it with NULL */
		hexkey = strchr(line, ':');
		if (! hexkey)
			continue;
		*hexkey = 0;
		hexkey++;

		/* Remove newline(s) at the end */
		for (i = strlen(hexkey) - 1; i && (hexkey[i] == '\n' || hexkey[i] == '\r'); i--)
			hexkey[i] = 0;

		if (identity == NULL || ! identity[0] || ! strcmp(line, identity)) {
			/* If the line starts with identity: or identity is not provided, parse this line. */
			psk_len = _tls_psk_decode_key(line, hexkey, psk, max_psk_len);
			if (psk_len)
				debug(("Loaded TLS-PSK '%.100s' from keyfile '%.100s'",
				       line, tls_psk_key_filename));
			else
				warning(("Failed loading TLS-PSK '%.100s' from keyfile '%.100s'",
					 line, tls_psk_key_filename));
			break;
		}
	}
	close(fd);

	return psk_len;
}

/* Client side TLS-PSK initialization callback. Indicate to OpenSSL what identity to
 * use, and the pre-shared key for that identity.
 *
 * Returns the number of bytes put in psk, or 0 on failure.
 */
static unsigned int
_tls_psk_client_cb(SSL *ssl, const char *hint,
		   char *identity, unsigned int max_identity_len,
		   unsigned char *psk, unsigned int max_psk_len)
{
	/* Client tells server which identity it wants to use in ClientKeyExchange */
	snprintf(identity, max_identity_len, "%s", tls_psk_identity);

	/* We currently just discard the hint sent to us by the server */
	return _tls_psk_server_cb(ssl, identity, psk, max_psk_len);
}


/* Initialize OpenSSL and create an SSL CTX. Should be called just once.
 *
 * Returns 0 on failure and 1 on success.
 */
int
gck_rpc_init_tls_psk(GckRpcTlsPskCtx *tls_ctx, const char *key_filename,
		     const char *identity, enum gck_rpc_tls_psk_caller caller)
{
	char *tls_psk_ciphers = PKCS11PROXY_TLS_PSK_CIPHERS;

	if (tls_ctx->initialized == 1) {
		warning(("TLS context already initialized"));
		return 0;
	}

	assert(caller == GCK_RPC_TLS_PSK_CLIENT || caller == GCK_RPC_TLS_PSK_SERVER);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	tls_ctx->libctx = OSSL_LIB_CTX_new();
	if (tls_ctx->libctx == NULL) {
		gck_rpc_warn("failed to create OpenSSL library context");
		return 0;
	}
	tls_ctx->ssl_ctx = SSL_CTX_new_ex(tls_ctx->libctx, NULL, TLS_method());
#else
	/* Global OpenSSL initialization (legacy) */
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_ssl_algorithms();
	tls_ctx->ssl_ctx = SSL_CTX_new(TLS_method());
#endif

	if (tls_ctx->ssl_ctx == NULL) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		OSSL_LIB_CTX_free(tls_ctx->libctx);
		tls_ctx->libctx = NULL;
#endif
		gck_rpc_warn("can't initialize SSL_CTX");
		return 0;
	}

	/* Set minimal version to TLS 1.2 */
	if (!SSL_CTX_set_min_proto_version(tls_ctx->ssl_ctx, TLS1_2_VERSION))	{
		SSL_CTX_free(tls_ctx->ssl_ctx);
		tls_ctx->ssl_ctx = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		OSSL_LIB_CTX_free(tls_ctx->libctx);
		tls_ctx->libctx = NULL;
#endif
		gck_rpc_warn("cannot set minimal protocol version to TLS 1.2");
		return 0;
	}

	/* Set maximal version to TLS 1.2 */
	if (!SSL_CTX_set_max_proto_version(tls_ctx->ssl_ctx, TLS1_2_VERSION)) {
		SSL_CTX_free(tls_ctx->ssl_ctx);
		tls_ctx->ssl_ctx = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		OSSL_LIB_CTX_free(tls_ctx->libctx);
		tls_ctx->libctx = NULL;
#endif
		gck_rpc_warn("cannot set maximal protocol version to TLS 1.2");
		return 0;
	}

	/* Set up callback for TLS-PSK initialization */
	if (caller == GCK_RPC_TLS_PSK_CLIENT)
		SSL_CTX_set_psk_client_callback(tls_ctx->ssl_ctx, _tls_psk_client_cb);
	else
		SSL_CTX_set_psk_server_callback(tls_ctx->ssl_ctx, _tls_psk_server_cb);

	/* Disable compression, for security (CRIME Attack). */
	SSL_CTX_set_options(tls_ctx->ssl_ctx, SSL_OP_NO_COMPRESSION);

	/* Specify ciphers to use */
	SSL_CTX_set_cipher_list(tls_ctx->ssl_ctx, tls_psk_ciphers);

	snprintf(tls_psk_key_filename, sizeof(tls_psk_key_filename), "%s", key_filename);

	/* Let the client tell the server which identity it uses.
	 * The server doesn't try to find an identity, it'll either accept the first one, or use the hint sent by the client */
	if (caller == GCK_RPC_TLS_PSK_CLIENT && !identity) {
		char line[1024], *hexkey;
		int fd;

		/* Parse the psk file just to find the identity, and use the first line */
		if ((fd = open(tls_psk_key_filename, O_RDONLY | O_CLOEXEC)) < 0) {
			gck_rpc_warn("can't open TLS-PSK keyfile '%.100s' for reading : %s",
					tls_psk_key_filename, strerror(errno));
			return 0;
		}

		if (gck_rpc_fgets(line, sizeof(line) - 1, fd) > 0) {
			/* Find first colon and set it to null => line is now identity */
			hexkey = strchr(line, ':');
			if (hexkey) {
				*hexkey = 0;
				/* Client tells server which identity it wants to use in ClientKeyExchange */
				snprintf(tls_psk_identity, sizeof(tls_psk_identity), "%s", line);
			}
		}
		close(fd);
	}

	tls_ctx->type = caller;
	tls_ctx->initialized = 1;

	debug(("Initialized TLS-PSK %s", caller == GCK_RPC_TLS_PSK_CLIENT ? "client" : "server"));

	return 1;
}

/* Set up SSL for a new socket. Call this after accept() or connect().
 *
 * When a socket has been created, call gck_rpc_start_tls() with the TLS state
 * initialized using gck_rpc_init_tls_psk() and the new socket.
 *
 * Returns 1 on success and 0 on failure.
 */
int
gck_rpc_start_tls(GckRpcTlsPskState *state, int sock)
{
	int res;
	char buf[256];

	state->ssl = SSL_new(state->ctx->ssl_ctx);
	if (! state->ssl) {
		warning(("can't initialize SSL"));
		return 0;
	}

	state->bio = BIO_new_socket(sock, BIO_NOCLOSE);
	if (! state->bio) {
		warning(("can't initialize SSL BIO"));
		return 0;
	}

	SSL_set_bio(state->ssl, state->bio, state->bio);

	/* Set up callback for TLS-PSK initialization */
	if (state->ctx->type == GCK_RPC_TLS_PSK_CLIENT)
		res = SSL_connect(state->ssl);
	else
		res = SSL_accept(state->ssl);

	if (res != 1) {
		ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
		warning(("can't start TLS : %i/%i (%s perhaps)",
			 res, SSL_get_error(state->ssl, res), strerror(errno)));
		warning(("SSL ERR: %s", buf));
		return 0;
	}

	return 1;
}

/* Un-initialize everything SSL context related structs. Call this on application shut down.
 */
void
gck_rpc_close_tls_ctx(GckRpcTlsPskCtx *tls_ctx)
{
	if (tls_ctx->ssl_ctx) {
		SSL_CTX_free(tls_ctx->ssl_ctx);
		tls_ctx->ssl_ctx = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		OSSL_LIB_CTX_free(tls_ctx->libctx);
		tls_ctx->libctx = NULL;
#endif
	}
}

/* Un-initialize SSL.
 */
void
gck_rpc_close_tls_state(GckRpcTlsPskState *tls_state)
{
	if (tls_state->ssl) {
		SSL_free(tls_state->ssl);
		tls_state->ssl = NULL;
	}
}

/* Un-initialize all SSL.
 */
void
gck_rpc_close_tls_all(GckRpcTlsPskState *tls_state)
{
	if (tls_state->ctx)
		gck_rpc_close_tls_ctx(tls_state->ctx);
	gck_rpc_close_tls_state(tls_state);
}

/* Send data using SSL.
 *
 * Returns the number of bytes written or -1 on error.
 */
int
gck_rpc_tls_write_all(GckRpcTlsPskState *state, void *data, unsigned int len)
{
	int ret, ssl_err;
	char buf[256];

	assert(state);
	assert(data);
	assert(len > 0);

	ret = SSL_write(state->ssl, data, len);

	if (ret > 0)
		return ret;

	ssl_err = SSL_get_error(state->ssl, ret);

	switch (ssl_err) {
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		// Non-fatal, retry later
		return 0;

	case SSL_ERROR_ZERO_RETURN:
		// Connection closed cleanly
		warning(("SSL_write: connection closed"));
		return -1;

	case SSL_ERROR_SYSCALL:
		if (ret == 0) {
			warning(("SSL_write: syscall EOF"));
		} else {
			perror("SSL_write: syscall error");
		}
		return -1;

	default:
		// Print all queued OpenSSL errors
		while ((ssl_err = ERR_get_error())) {
			ERR_error_string_n(ssl_err, buf, sizeof(buf));
			warning(("SSL_write error: %s", buf));
		}
		return -1;
	}
}

/* Read data using SSL.
 *
 * Returns the number of bytes read or -1 on error.
 */
int
gck_rpc_tls_read_all(GckRpcTlsPskState *state, void *data, unsigned int len)
{
	int ret, ssl_err;
	char buf[256];

	assert(state);
	assert(data);
	assert(len > 0);

	ret = SSL_read(state->ssl, data, len);

	if (ret > 0)
		return ret;

	ssl_err = SSL_get_error(state->ssl, ret);

	switch (ssl_err) {
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		// Non-fatal, retry later
		return 0;

	case SSL_ERROR_ZERO_RETURN:
		// Connection closed cleanly
		warning(("SSL_read: connection closed"));
		return -1;

	case SSL_ERROR_SYSCALL:
		if (ret == 0) {
			warning(("SSL_read: syscall EOF"));
		} else {
			perror("SSL_read: syscall error");
		}
		return -1;

	default:
		// Print all queued OpenSSL errors
		while ((ssl_err = ERR_get_error())) {
			ERR_error_string_n(ssl_err, buf, sizeof(buf));
			warning(("SSL_read error: %s", buf));
		}
		return -1;
	}
}
