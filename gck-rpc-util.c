/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* p11-rpc-util.c - utilities for module and dispatcher

   Copyright (C) 2008, Stef Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gck-rpc-conf.h"
#include "gck-rpc-layer.h"
#include "gck-rpc-private.h"

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#ifdef __MINGW32__
# include <winsock2.h>
#else
# include <sys/socket.h>
# include <sys/time.h>
# include <arpa/inet.h>
# include <netinet/in.h>
# include <netinet/tcp.h>
# include <sys/types.h>
# include <netdb.h>
#endif

static void do_log(const char *pref, const char *msg, va_list va)
{
	char buffer[1024];
	size_t len = 0;

	if (pref) {
		snprintf(buffer, sizeof(buffer), "%s: ", pref);
		len = strlen(buffer);
	}

	vsnprintf(buffer + len, sizeof(buffer) - len, msg, va);
	gck_rpc_log(buffer);
}

void gck_rpc_warn(const char *msg, ...)
{
	va_list va;
	va_start(va, msg);
	do_log("WARNING", msg, va);
	va_end(va);
}

void gck_rpc_debug(const char *msg, ...)
{
	va_list va;
	va_start(va, msg);
	do_log("DEBUG", msg, va);
	va_end(va);
}

int gck_rpc_mechanism_is_supported(CK_MECHANISM_TYPE mech)
{
	return gck_rpc_mechanism_has_no_parameters(mech) ||
			gck_rpc_mechanism_has_sane_parameters(mech) ||
			gck_rpc_mechanism_is_edch_derive(mech);
}

void
gck_rpc_mechanism_list_purge(CK_MECHANISM_TYPE_PTR mechs, CK_ULONG * n_mechs)
{
	int i;

	assert(mechs);
	assert(n_mechs);

	for (i = 0; i < (int)(*n_mechs); ++i) {
		if (!gck_rpc_mechanism_is_supported(mechs[i])) {

			/* Remove the mechanism from the list */
			memmove(&mechs[i], &mechs[i + 1],
				(*n_mechs - i - 1) * sizeof(CK_MECHANISM_TYPE));

			--(*n_mechs);
			--i;
		}
	}
}

int gck_rpc_mechanism_is_edch_derive(CK_MECHANISM_TYPE type)
{
	switch (type) {
	case CKM_ECDH1_COFACTOR_DERIVE:
	case CKM_ECDH1_DERIVE:
		return 1;
	default:
		return 0;
	}
}

int gck_rpc_mechanism_has_sane_parameters(CK_MECHANISM_TYPE type)
{
	/* This list is incomplete */
	switch (type) {
	case CKM_RSA_PKCS_OAEP:
	case CKM_RSA_PKCS_PSS:
	/* Parameter is IV */
	case CKM_DES_CBC:
	case CKM_DES_CBC_PAD:
	case CKM_DES3_CBC:
	case CKM_DES3_CBC_PAD:
	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
		return 1;
	default:
		return 0;
	}
}

int gck_rpc_mechanism_has_no_parameters(CK_MECHANISM_TYPE mech)
{
	/* This list is incomplete */

	switch (mech) {
	case CKM_RSA_PKCS_KEY_PAIR_GEN:
	case CKM_RSA_X9_31_KEY_PAIR_GEN:
	case CKM_RSA_PKCS:
	case CKM_RSA_9796:
	case CKM_RSA_X_509:
	case CKM_RSA_X9_31:
	case CKM_MD2_RSA_PKCS:
	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
	case CKM_RIPEMD128_RSA_PKCS:
	case CKM_RIPEMD160_RSA_PKCS:
	case CKM_SHA1_RSA_X9_31:
	case CKM_DSA_KEY_PAIR_GEN:
	case CKM_DSA_PARAMETER_GEN:
	case CKM_DSA:
	case CKM_DSA_SHA1:
	case CKM_FORTEZZA_TIMESTAMP:
	case CKM_EC_KEY_PAIR_GEN:
	case CKM_ECDSA:
	case CKM_ECDSA_SHA1:
	case CKM_DH_PKCS_KEY_PAIR_GEN:
	case CKM_DH_PKCS_PARAMETER_GEN:
	case CKM_X9_42_DH_KEY_PAIR_GEN:
	case CKM_X9_42_DH_PARAMETER_GEN:
	case CKM_KEA_KEY_PAIR_GEN:
	case CKM_GENERIC_SECRET_KEY_GEN:
	case CKM_RC2_KEY_GEN:
	case CKM_RC4_KEY_GEN:
	case CKM_RC4:
	case CKM_RC5_KEY_GEN:
	case CKM_AES_KEY_GEN:
	case CKM_AES_ECB:
	case CKM_AES_MAC:
	case CKM_DES_KEY_GEN:
	case CKM_DES2_KEY_GEN:
	case CKM_DES3_KEY_GEN:
	case CKM_CDMF_KEY_GEN:
	case CKM_CAST_KEY_GEN:
	case CKM_CAST3_KEY_GEN:
	case CKM_CAST128_KEY_GEN:
	case CKM_IDEA_KEY_GEN:
	case CKM_SSL3_PRE_MASTER_KEY_GEN:
	case CKM_TLS_PRE_MASTER_KEY_GEN:
	case CKM_SKIPJACK_KEY_GEN:
	case CKM_BATON_KEY_GEN:
	case CKM_JUNIPER_KEY_GEN:
	case CKM_RC2_ECB:
	case CKM_DES_ECB:
	case CKM_DES3_ECB:
	case CKM_CDMF_ECB:
	case CKM_CAST_ECB:
	case CKM_CAST3_ECB:
	case CKM_CAST128_ECB:
	case CKM_RC5_ECB:
	case CKM_IDEA_ECB:
	case CKM_RC2_MAC:
	case CKM_DES_MAC:
	case CKM_DES3_MAC:
	case CKM_CDMF_MAC:
	case CKM_CAST_MAC:
	case CKM_CAST3_MAC:
	case CKM_RC5_MAC:
	case CKM_IDEA_MAC:
	case CKM_SSL3_MD5_MAC:
	case CKM_SSL3_SHA1_MAC:
	case CKM_SKIPJACK_WRAP:
	case CKM_BATON_WRAP:
	case CKM_JUNIPER_WRAP:
	case CKM_MD2:
	case CKM_MD2_HMAC:
	case CKM_MD5:
	case CKM_MD5_HMAC:
	case CKM_SHA_1:
	case CKM_SHA_1_HMAC:
	case CKM_SHA256:
	case CKM_SHA256_HMAC:
	case CKM_SHA384:
	case CKM_SHA384_HMAC:
	case CKM_SHA512:
	case CKM_SHA512_HMAC:
	case CKM_FASTHASH:
	case CKM_RIPEMD128:
	case CKM_RIPEMD128_HMAC:
	case CKM_RIPEMD160:
	case CKM_RIPEMD160_HMAC:
	case CKM_KEY_WRAP_LYNKS:
		return 1;
	default:
		return 0;
	};
}

int
gck_rpc_has_ulong_parameter(CK_ATTRIBUTE_TYPE type)
{
	switch (type) {
	case CKA_CLASS:
	case CKA_KEY_TYPE:
	case CKA_CERTIFICATE_TYPE:
	case CKA_HW_FEATURE_TYPE:
        case CKA_MODULUS_BITS:
		return 1;
	default:
		return 0;
	}
}

int
gck_rpc_has_bad_sized_ulong_parameter(CK_ATTRIBUTE_PTR attr)
{
	if (!attr->pValue)
		return 0;
	/* All this parameters are transmited on the network
	 * as 64bit integers */
	if (sizeof (uint64_t) != attr->ulValueLen)
		return 0;
	if (sizeof (CK_ULONG) == attr->ulValueLen)
		return 0;
	return gck_rpc_has_ulong_parameter(attr->type);
}

/*
 * Parses prefix into two strings (host and port). Port may be a NULL pointer
 * if none is specified. Since this code does not decode port in any way, a
 * service name works too (but requires other code (like
 * _get_listening_socket()) able to resolve service names).
 *
 * This should work for IPv4 and IPv6 inputs :
 *
 *   0.0.0.0:2345
 *   0.0.0.0
 *   [::]:2345
 *   [::]
 *   [::1]:2345
 *   localhost:2345
 *   localhost
 *   localhost:p11proxy   (if p11proxy is a known service name)
 *
 * Returns 0 on failure, and 1 on success.
 */
int gck_rpc_parse_host_port(const char *prefix, char **host, char **port)
{
	char *p = NULL;
	int is_ipv6;

	is_ipv6 = (prefix[0] == '[') ? 1 : 0;

	*host = strdup(prefix + is_ipv6);
	*port = NULL;

	if (*host == NULL) {
		gck_rpc_warn("out of memory");
		return 0;
	}

	if (is_ipv6 && prefix[0] == '[')
		p = strchr(*host, ']');
	else
		p = strchr(*host, ':');

	if (p) {
		is_ipv6 = (*p == ']'); /* remember if separator was ']' */

		*p = '\0'; /* replace separator will NULL to terminate *host */
		*port = p + 1;

		if (is_ipv6 && (**port == ':'))
			*port = p + 2;
	}

	return 1;
}

/* Set client/server common socket options */
int gck_rpc_set_common_sock_options(int sock, const char *host, const char *port)
{
	int one = 1;

    int so_recv_timeout = gck_rpc_conf_get_so_recv_timeout();
    if (so_recv_timeout >= 0) {
        struct timeval timeout = {
            .tv_sec = so_recv_timeout,
            .tv_usec = 0
        };

        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
            gck_rpc_warn("couldn't set receive timeout (%.100s %.100s): %.100s",
                         host, port, strerror(errno));
            return 0;
        }
    }

	if (gck_rpc_conf_get_so_keepalive()) {
		if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char *)&one, sizeof(one)) == -1) {
			gck_rpc_warn
				("couldn't set pkcs11 SO_KEEPALIVE socket option (%.100s %.100s): %.100s",
				host, port, strerror(errno));
			return 0;
		}

#ifdef TCP_KEEPIDLE
        int keepidle = gck_rpc_conf_get_tcp_keepidle();
        if (keepidle >= 0) {
            if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle)) == -1) {
                gck_rpc_warn("couldn't set pkcs11 TCP_KEEPIDLE option (%.100s %.100s): %.100s",
                             host, port, strerror(errno));
                return 0;
            }
        }
#endif

#ifdef TCP_KEEPINTVL
        int keepintvl = gck_rpc_conf_get_tcp_keepintvl();
        if (keepintvl >= 0) {
            if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl)) == -1) {
                gck_rpc_warn("couldn't set pkcs11 TCP_KEEPINTVL option (%.100s %.100s): %.100s",
                             host, port, strerror(errno));
                return 0;
            }
        }
#endif

#ifdef TCP_KEEPCNT
        int keepcnt = gck_rpc_conf_get_tcp_keepcnt();
        if (keepcnt >= 0) {
            if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt)) == -1) {
                gck_rpc_warn("couldn't set pkcs11 TCP_KEEPCNT option (%.100s %.100s): %.100s",
                             host, port, strerror(errno));
                return 0;
            }
        }
#endif
	}

	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof (one)) == -1) {
		gck_rpc_warn("couldn't set pkcs11 socket protocol options (%.100s %.100s): %.100s",
				host, port, strerror(errno));
		return 0;
	}

	return 1;
}

/*
 * Read from a file descriptor until a newline is spotted.
 *
 * Using open() and gck_rpc_fgets() instead of fopen() and fgets() avoids having to
 * seccomp-allow the mmap() syscall.
 *
 * Reading one byte at a time is perhaps not optimal from a performance
 * standpoint, but the kernel will surely have pre-buffered the data anyways.
 */
int gck_rpc_fgets(char *buf, unsigned int len, const int fd)
{
	int bytes;

	bytes = 0;

	while (len) {
		if (read(fd, buf, 1) != 1)
			break;
		bytes++;
		if (*buf == '\n') {
			buf++;
			len--;
			break;
		}
		buf++;
		len--;
	}

	if (! len)
		/* ran out of space */
		return -1;
	*buf = '\0';
	return bytes;
}
