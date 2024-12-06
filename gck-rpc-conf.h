/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-rpc-conf.h - Configuration wrapper

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

#ifndef GCK_RPC_CONF_H
#define GCK_RPC_CONF_H

#include <stdbool.h>

// Configuration initialization and parsing
bool gck_rpc_conf_init(void);

// Getters for configuration values
const char *gck_rpc_conf_get_so_path(const char *env);
const char *gck_rpc_conf_get_tls_psk_file(const char *env);
int gck_rpc_conf_get_so_recv_timeout(void);
bool gck_rpc_conf_get_so_keepalive(void);
int gck_rpc_conf_get_tcp_keepidle(void);
int gck_rpc_conf_get_tcp_keepintvl(void);
int gck_rpc_conf_get_tcp_keepcnt(void);

#endif // GCK_RPC_CONF_H