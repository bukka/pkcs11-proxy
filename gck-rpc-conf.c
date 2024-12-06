/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-rpc-conf.c - Configuration wrapper

   Copyright (C) 2024, Jakub Zelenka

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
*/

#include "gck-rpc-conf.h"
#include "gck-rpc-private.h"
#include <fcntl.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define GCK_RPC_DEFAULT_CONF_PATH "/etc/pkcs11-proxy.conf"
#define GCK_RPC_LINE_BUFFER_SIZE 1024

typedef struct {
	char so_path[1024];
	int so_recv_timeout;
	bool so_keepalive;
	int tcp_keepidle;
	int tcp_keepintvl;
	int tcp_keepcnt;
	char psk_file[2048];
} gck_rpc_config_t;

static gck_rpc_config_t gck_rpc_config;

// Helper functions
static char *gck_rpc_trim_whitespace(char *str)
{
	char *end;
	while (isspace((unsigned char)*str)) {
		str++;
	}
	if (*str == 0) {
		return str;
	}
	end = str + strlen(str) - 1;
	while (end > str && isspace((unsigned char)*end)) {
		end--;
	}
	*(end + 1) = '\0';
	return str;
}

static void gck_rpc_set_string(const char *raw_value, void *dest)
{
	strncpy((char *)dest, raw_value, 255);
}

static void gck_rpc_set_int(const char *raw_value, void *dest)
{
	*(int *)dest = atoi(raw_value);
}

static void gck_rpc_set_bool(const char *raw_value, void *dest)
{
	*(bool *)dest = (strcasecmp(raw_value, "true") == 0 || strcmp(raw_value, "1") == 0);
}

// Configuration options
static struct {
	const char *key;
	void *value;
	void (*setter)(const char *raw_value, void *dest);
} gck_rpc_config_options[] = {
	{"so_path", gck_rpc_config.so_path, gck_rpc_set_string},
	{"so_recv_timeout", &gck_rpc_config.so_recv_timeout, gck_rpc_set_int},
	{"so_keepalive", &gck_rpc_config.so_keepalive, gck_rpc_set_bool},
	{"tcp_keepidle", &gck_rpc_config.tcp_keepidle, gck_rpc_set_int},
	{"tcp_keepintvl", &gck_rpc_config.tcp_keepintvl, gck_rpc_set_int},
	{"tcp_keepcnt", &gck_rpc_config.tcp_keepcnt, gck_rpc_set_int},
	{"psk_file", gck_rpc_config.psk_file, gck_rpc_set_string},
	{NULL, NULL, NULL} // Sentinel
};

static void gck_rpc_set_defaults(void)
{
	gck_rpc_config.so_recv_timeout = -1;
	gck_rpc_config.so_keepalive = false;
	gck_rpc_config.tcp_keepidle = -1;
	gck_rpc_config.tcp_keepintvl = -1;
	gck_rpc_config.tcp_keepcnt = -1;
	gck_rpc_config.so_path[0] = '\0';
	gck_rpc_config.psk_file[0] = '\0';
}

static bool gck_rpc_parse_config_file(const char *filename)
{
	int fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("Error opening config file");
		return false;
	}

	char line[GCK_RPC_LINE_BUFFER_SIZE];
	while (gck_rpc_fgets(line, sizeof(line), fd)) {
		char *trimmed = gck_rpc_trim_whitespace(line);

		if (*trimmed == '\0' || *trimmed == '#') continue;

		char *delimiter = strchr(trimmed, '=');
		if (!delimiter) {
			fprintf(stderr, "Invalid config line: %s\n", trimmed);
			continue;
		}

		*delimiter = '\0';
		char *key = gck_rpc_trim_whitespace(trimmed);
		char *value = gck_rpc_trim_whitespace(delimiter + 1);

		bool matched = false;
		for (int i = 0; gck_rpc_config_options[i].key != NULL; ++i) {
			if (strcmp(gck_rpc_config_options[i].key, key) == 0) {
				gck_rpc_config_options[i].setter(value, gck_rpc_config_options[i].value);
				matched = true;
				break;
			}
		}

		if (!matched) {
			fprintf(stderr, "Unknown key in config: %s\n", key);
		}
	}

	close(fd);
	return true;
}

// Public API
bool gck_rpc_conf_init(void)
{
	gck_rpc_set_defaults();
	const char *config_path = getenv("PKCS11_PROXY_CONF_PATH");
	if (!config_path) {
		return true;
	}
	return gck_rpc_parse_config_file(config_path);
}

const char *gck_rpc_conf_get_so_path(const char *env)
{
	const char *env_value = getenv(env);
	if (env_value && strlen(env_value) > 0) {
		return env_value;
	}
	return gck_rpc_config.so_path[0] ? gck_rpc_config.so_path : NULL;
}

const char *gck_rpc_conf_get_tls_psk_file(const char *env)
{
	const char *env_value = getenv(env);
	if (env_value && strlen(env_value) > 0) {
		return env_value;
	}
	return gck_rpc_config.psk_file[0] ? gck_rpc_config.psk_file : NULL;
}

int gck_rpc_conf_get_so_recv_timeout(void)
{
    return gck_rpc_config.so_recv_timeout;
}

bool gck_rpc_conf_get_so_keepalive(void)
{
	return gck_rpc_config.so_keepalive;
}

int gck_rpc_conf_get_tcp_keepidle(void)
{
	return gck_rpc_config.tcp_keepidle;
}

int gck_rpc_conf_get_tcp_keepintvl(void)
{
	return gck_rpc_config.tcp_keepintvl;
}

int gck_rpc_conf_get_tcp_keepcnt(void)
{
	return gck_rpc_config.tcp_keepcnt;
}
