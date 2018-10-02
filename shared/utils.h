/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2010 Red Hat, Inc.
 */

#ifndef UTILS_H
#define UTILS_H

#define NMV_WG_TAG_INTERFACE			"[Interface]"
#define NMV_WG_TAG_PRIVATE_KEY			"PrivateKey"
#define NMV_WG_TAG_LISTEN_PORT			"ListenPort"
#define NMV_WG_TAG_ADDRESS				"Address"
#define NMV_WG_TAG_DNS                  "DNS"
#define NMV_WG_TAG_MTU                  "MTU"
#define NMV_WG_TAG_PRE_UP               "PreUp"
#define NMV_WG_TAG_POST_UP				"PostUp"
#define NMV_WG_TAG_PRE_DOWN             "PreDown"
#define NMV_WG_TAG_POST_DOWN			"PostDown"
#define NMV_WG_TAG_PRESHARED_KEY		"PresharedKey"
#define NMV_WG_TAG_PEER					"[Peer]"
#define NMV_WG_TAG_PUBLIC_KEY			"PublicKey"
#define NMV_WG_TAG_ALLOWED_IPS			"AllowedIPs"
#define NMV_WG_TAG_ENDPOINT				"Endpoint"
#define NMV_WG_TAG_PERSISTENT_KEEP_ALIVE    "PersistentKeepalive"

#define NMV_OVPN_TAG_AUTH               "auth"
#define NMV_OVPN_TAG_AUTH_NOCACHE       "auth-nocache"
#define NMV_OVPN_TAG_AUTH_USER_PASS     "auth-user-pass"
#define NMV_OVPN_TAG_CA                 "ca"
#define NMV_OVPN_TAG_CERT               "cert"
#define NMV_OVPN_TAG_CIPHER             "cipher"
#define NMV_OVPN_TAG_CLIENT             "client"
#define NMV_OVPN_TAG_COMP_LZO           "comp-lzo"
#define NMV_OVPN_TAG_DEV                "dev"
#define NMV_OVPN_TAG_DEV_TYPE           "dev-type"
#define NMV_OVPN_TAG_FLOAT              "float"
#define NMV_OVPN_TAG_FRAGMENT           "fragment"
#define NMV_OVPN_TAG_GROUP              "group"
#define NMV_OVPN_TAG_HTTP_PROXY         "http-proxy"
#define NMV_OVPN_TAG_HTTP_PROXY_RETRY   "http-proxy-retry"
#define NMV_OVPN_TAG_IFCONFIG           "ifconfig"
#define NMV_OVPN_TAG_KEEPALIVE          "keepalive"
#define NMV_OVPN_TAG_KEY_DIRECTION      "key-direction"
#define NMV_OVPN_TAG_KEY                "key"
#define NMV_OVPN_TAG_KEYSIZE            "keysize"
#define NMV_OVPN_TAG_MAX_ROUTES         "max-routes"
#define NMV_OVPN_TAG_MSSFIX             "mssfix"
#define NMV_OVPN_TAG_MTU_DISC           "mtu-disc"
#define NMV_OVPN_TAG_NOBIND             "nobind"
#define NMV_OVPN_TAG_NS_CERT_TYPE       "ns-cert-type"
#define NMV_OVPN_TAG_PERSIST_KEY        "persist-key"
#define NMV_OVPN_TAG_PERSIST_TUN        "persist-tun"
#define NMV_OVPN_TAG_PING_EXIT          "ping-exit"
#define NMV_OVPN_TAG_PING               "ping"
#define NMV_OVPN_TAG_PING_RESTART       "ping-restart"
#define NMV_OVPN_TAG_PKCS12             "pkcs12"
#define NMV_OVPN_TAG_PORT               "port"
#define NMV_OVPN_TAG_PROTO              "proto"
#define NMV_OVPN_TAG_REMOTE_CERT_TLS    "remote-cert-tls"
#define NMV_OVPN_TAG_REMOTE_RANDOM      "remote-random"
#define NMV_OVPN_TAG_REMOTE             "remote"
#define NMV_OVPN_TAG_RENEG_SEC          "reneg-sec"
#define NMV_OVPN_TAG_ROUTE              "route"
#define NMV_OVPN_TAG_RPORT              "rport"
#define NMV_OVPN_TAG_SCRIPT_SECURITY    "script-security"
#define NMV_OVPN_TAG_SECRET             "secret"
#define NMV_OVPN_TAG_SOCKS_PROXY_RETRY  "socks-proxy-retry"
#define NMV_OVPN_TAG_SOCKS_PROXY        "socks-proxy"
#define NMV_OVPN_TAG_TLS_AUTH           "tls-auth"
#define NMV_OVPN_TAG_TLS_CIPHER         "tls-cipher"
#define NMV_OVPN_TAG_TLS_CLIENT         "tls-client"
#define NMV_OVPN_TAG_TLS_CRYPT          "tls-crypt"
#define NMV_OVPN_TAG_TLS_REMOTE         "tls-remote"
#define NMV_OVPN_TAG_TOPOLOGY           "topology"
#define NMV_OVPN_TAG_TUN_IPV6           "tun-ipv6"
#define NMV_OVPN_TAG_TUN_MTU            "tun-mtu"
#define NMV_OVPN_TAG_USER               "user"
#define NMV_OVPN_TAG_VERIFY_X509_NAME   "verify-x509-name"

gboolean is_pkcs12 (const char *filepath);

gboolean is_encrypted (const char *filename);

gboolean is_empty(const char *str);

gboolean is_ip4 (char *addr);

gboolean is_ip6 (char *addr);

gboolean is_fqdn(char *addr);

gboolean is_base64(char *str);

#define NMOVPN_PROTCOL_TYPES \
	"udp", \
	"udp4", \
	"udp6", \
	"tcp", \
	"tcp4", \
	"tcp6", \
	"tcp-client", \
	"tcp4-client", \
	"tcp6-client"

gssize nmovpn_remote_parse (const char *str,
                            char **out_buf,
                            const char **out_host,
                            const char **out_port,
                            const char **out_proto,
                            GError **error);

#endif  /* UTILS_H */
