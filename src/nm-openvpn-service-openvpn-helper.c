/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-openvpn-service-openvpn-helper - helper called after OpenVPN established
 * a connection, uses DBUS to send information back to nm-openvpn-service
 *
 * Tim Niemueller [www.niemueller.de]
 * Based on work by Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2005 Red Hat, Inc.
 * (C) Copyright 2005 Tim Niemueller
 *
 * $Id: nm-openvpn-service-openvpn-helper.c 4170 2008-10-11 14:44:45Z dcbw $
 */

#include "nm-default.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <regex.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <syslog.h>

#include "nm-utils/nm-shared-utils.h"
#include "nm-utils/nm-vpn-plugin-macros.h"

extern char **environ;

static struct {
	int log_level;
	const char *log_prefix_token;
} gl;

/*****************************************************************************/

#define _NMLOG(level, ...) \
	G_STMT_START { \
		if (gl.log_level >= (level)) { \
			g_print ("nm-openvpn[%s]: %-7s [helper-%ld] " _NM_UTILS_MACRO_FIRST (__VA_ARGS__) "\n", \
			         gl.log_prefix_token ?: "???", \
			         nm_utils_syslog_to_str (level), \
			         (long) getpid () \
			         _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
		} \
	} G_STMT_END

static inline gboolean
_LOGD_enabled (void)
{
	return gl.log_level >= LOG_INFO;
}

#define _LOGD(...) _NMLOG(LOG_INFO,    __VA_ARGS__)
#define _LOGI(...) _NMLOG(LOG_NOTICE,  __VA_ARGS__)
#define _LOGW(...) _NMLOG(LOG_WARNING, __VA_ARGS__)

/*****************************************************************************/

static void
helper_failed (GDBusProxy *proxy, const char *reason)
{
	GError *err = NULL;

	_LOGW ("nm-openvpn-service-openvpn-helper did not receive a valid %s from openvpn", reason);

	if (!g_dbus_proxy_call_sync (proxy, "SetFailure",
	                             g_variant_new ("(s)", reason),
	                             G_DBUS_CALL_FLAGS_NONE, -1,
	                             NULL,
	                             &err)) {
		_LOGW ("Could not send failure information: %s", err->message);
		g_error_free (err);
	}

	exit (1);
}

static void
send_config (GDBusProxy *proxy, GVariant *config,
             GVariant *ip4config, GVariant *ip6config)
{
	GError *err = NULL;

	if (!g_dbus_proxy_call_sync (proxy, "SetConfig",
	                             g_variant_new ("(*)", config),
	                             G_DBUS_CALL_FLAGS_NONE, -1,
	                             NULL,
	                             &err)) {
		_LOGW ("Could not send configuration information: %s", err->message);
		g_error_free (err);
		err = NULL;
	}

	if (ip4config) {
	        if (!g_dbus_proxy_call_sync (proxy, "SetIp4Config",
	                                     g_variant_new ("(*)", ip4config),
	                                     G_DBUS_CALL_FLAGS_NONE, -1,
	                                     NULL,
		                             &err)) {
			_LOGW ("Could not send IPv4 configuration information: %s", err->message);
			g_error_free (err);
			err = NULL;
		}
	}

	if (ip6config) {
	        if (!g_dbus_proxy_call_sync (proxy, "SetIp6Config",
	                                     g_variant_new ("(*)", ip6config),
	                                     G_DBUS_CALL_FLAGS_NONE, -1,
	                                     NULL,
		                             &err)) {
			_LOGW ("Could not send IPv6 configuration information: %s", err->message);
			g_error_free (err);
			err = NULL;
		}
	}
}

static GVariant *
str_to_gvariant (const char *str, gboolean try_convert)
{
	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (!g_utf8_validate (str, -1, NULL)) {
		if (try_convert && !(str = g_convert (str, -1, "ISO-8859-1", "UTF-8", NULL, NULL, NULL)))
			str = g_convert (str, -1, "C", "UTF-8", NULL, NULL, NULL);

		if (!str)
			/* Invalid */
			return NULL;
	}

	return g_variant_new_string (str);
}

static GVariant *
addr4_to_gvariant (const char *str)
{
	struct in_addr	temp_addr;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (inet_pton (AF_INET, str, &temp_addr) <= 0)
		return NULL;

	return g_variant_new_uint32 (temp_addr.s_addr);
}

static GVariant *
addr6_to_gvariant (const char *str)
{
	struct in6_addr temp_addr;
	GVariantBuilder builder;
	int i;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (inet_pton (AF_INET6, str, &temp_addr) <= 0)
		return NULL;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("ay"));
	for (i = 0; i < sizeof (temp_addr); i++)
		g_variant_builder_add (&builder, "y", ((guint8 *) &temp_addr)[i]);
	return g_variant_builder_end (&builder);
}

static void
parse_addr_list (GPtrArray *array4, GPtrArray *array6, const char *str)
{
	char **split;
	int i;
	GVariant *variant;

	/* Empty */
	if (!str || strlen (str) < 1)
		return;

	split = g_strsplit (str, " ", -1);
	for (i = 0; split[i]; i++) {
		if (array4 && (variant = addr4_to_gvariant (split[i])) != NULL)
			g_ptr_array_add (array4, variant);
		else if (array6 && (variant = addr6_to_gvariant (split[i])) != NULL)
			g_ptr_array_add (array6, variant);
	}

	g_strfreev (split);

	return;
}

static inline gboolean
is_domain_valid (const char *str)
{
	return (str && (strlen(str) >= 1) && (strlen(str) <= 255));
}

static GVariant *
get_ip4_routes (void)
{
	GVariantBuilder builder;
	char *tmp;
	gboolean has_any = FALSE;
	guint i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aau"));

	for (i = 1;; i++) {
		GVariantBuilder array;
		char key_name[255];
		in_addr_t network;
		in_addr_t netmask;
		in_addr_t gateway = 0;
		guint32 metric;

		nm_sprintf_buf (key_name, "route_network_%u", i);
		tmp = getenv (key_name);
		if (!tmp || !tmp[0])
			break;

		if (inet_pton (AF_INET, tmp, &network) != 1) {
			_LOGW ("Ignoring invalid static route address %s = \"%s\"", key_name, tmp);
			continue;
		}

		nm_sprintf_buf (key_name, "route_netmask_%u", i);
		tmp = getenv (key_name);
		if (   !tmp
		    || inet_pton (AF_INET, tmp, &netmask) != 1) {
			_LOGW ("Ignoring invalid static route netmask %s = %s%s%s", key_name, NM_PRINT_FMT_QUOTE_STRING (tmp));
			continue;
		}

		nm_sprintf_buf (key_name, "route_gateway_%u", i);
		tmp = getenv (key_name);
		/* gateway can be missing */
		if (   tmp
		    && inet_pton (AF_INET, tmp, &gateway) != 1) {
			_LOGW ("Ignoring invalid static route gateway %s = \"%s\"", key_name, tmp);
			continue;
		}

		nm_sprintf_buf (key_name, "route_metric_%u", i);
		tmp = getenv (key_name);
		/* metric can be missing */
		if (tmp && tmp[0]) {
			metric = _nm_utils_ascii_str_to_int64 (tmp, 10, 0, G_MAXUINT32, 0);
			if (errno) {
				_LOGW ("Ignoring invalid static route metric %s = \"%s\"", key_name, tmp);
				continue;
			}
		} else
			metric = 0;

		g_variant_builder_init (&array, G_VARIANT_TYPE ("au"));
		g_variant_builder_add_value (&array, g_variant_new_uint32 (network));
		g_variant_builder_add_value (&array, g_variant_new_uint32 (nm_utils_ip4_netmask_to_prefix (netmask)));
		g_variant_builder_add_value (&array, g_variant_new_uint32 (gateway));
		g_variant_builder_add_value (&array, g_variant_new_uint32 (metric));
		g_variant_builder_add_value (&builder, g_variant_builder_end (&array));
		has_any = TRUE;
	}

	if (!has_any) {
		g_variant_builder_clear (&builder);
		return NULL;
	}

	return g_variant_builder_end (&builder);
}

static GVariant *
get_ip6_routes (void)
{
	gs_unref_ptrarray GPtrArray *routes = NULL;
	guint i;

	routes = g_ptr_array_new_full (10, (GDestroyNotify) nm_ip_route_unref);

	for (i = 1;; i++) {
		NMIPRoute *route;
		GError *error = NULL;
		gs_free char *dst = NULL;
		char key_name[255];
		int prefix;
		const char *tmp;

		nm_sprintf_buf (key_name, "route_ipv6_network_%u", i);
		tmp = getenv (key_name);
		if (!tmp || !tmp[0])
			break;

		if (   !nm_utils_parse_inaddr_prefix (tmp, AF_INET6, &dst, &prefix)
		    || prefix == -1) {
			_LOGW ("Ignoring invalid static route %s = \"%s\"", key_name, tmp);
			continue;
		}

		nm_sprintf_buf (key_name, "route_ipv6_gateway_%u", i);
		tmp = getenv (key_name);

		route = nm_ip_route_new (AF_INET6, dst, prefix, tmp, -1, &error);
		if (!route) {
			_LOGW ("Ignoring route#%u: %s", i, error->message);
			g_error_free (error);
			continue;
		}

		g_ptr_array_add (routes, route);
	}

	if (!routes->len)
		return NULL;

	return nm_utils_ip6_routes_to_variant (routes);
}

static GVariant *
trusted_remote_to_gvariant (void)
{
	char *tmp;
	GVariant *val = NULL;
	const char *p;
	gboolean is_name = FALSE;

	tmp = getenv ("trusted_ip6");
	if (tmp) {
		val = addr6_to_gvariant (tmp);
		if (val == NULL) {
			_LOGW ("failed to convert VPN gateway address '%s' (%d)",
			       tmp, errno);
			return NULL;
		}
		return val;
	}

	tmp = getenv ("trusted_ip");
	if (!tmp)
		tmp = getenv ("remote_1");
	if (!tmp) {
		_LOGW ("did not receive remote gateway address");
		return NULL;
	}

	/* Check if it seems to be a hostname */
	p = tmp;
	while (*p) {
		if (*p != '.' && !isdigit (*p)) {
			is_name = TRUE;
			break;
		}
		p++;
	}

	/* Resolve a hostname if required. Only look for IPv4 addresses */
	if (is_name) {
		struct in_addr addr;
		struct addrinfo hints;
		struct addrinfo *result = NULL, *rp;
		int err;

		addr.s_addr = 0;
		memset (&hints, 0, sizeof (hints));

		hints.ai_family = AF_INET;
		hints.ai_flags = AI_ADDRCONFIG;
		err = getaddrinfo (tmp, NULL, &hints, &result);
		if (err != 0) {
			_LOGW ("failed to look up VPN gateway address '%s' (%d)",
			       tmp, err);
			return NULL;
		}

		/* FIXME: so what if the name resolves to multiple IP addresses?  We
		 * don't know which one pptp decided to use so we could end up using a
		 * different one here, and the VPN just won't work.
		 */
		for (rp = result; rp; rp = rp->ai_next) {
			if (   (rp->ai_family == AF_INET)
			    && (rp->ai_addrlen == sizeof (struct sockaddr_in))) {
				struct sockaddr_in *inptr = (struct sockaddr_in *) rp->ai_addr;

				memcpy (&addr, &(inptr->sin_addr), sizeof (struct in_addr));
				break;
			}
		}

		freeaddrinfo (result);
		if (addr.s_addr != 0)
			return g_variant_new_uint32 (addr.s_addr);
		else {
			_LOGW ("failed to convert or look up VPN gateway address '%s'",
			       tmp);
			return NULL;
		}
	} else {
		val = addr4_to_gvariant (tmp);
		if (val == NULL) {
			_LOGW ("failed to convert VPN gateway address '%s' (%d)",
			       tmp, errno);
			return NULL;
		}
	}

	return val;
}

int
main (int argc, char *argv[])
{
	GDBusProxy *proxy;
	GVariantBuilder builder, ip4builder, ip6builder;
	GVariant *ip4config, *ip6config;
	char *tmp;
	GVariant *val;
	int i;
	GError *err = NULL;
	GPtrArray *dns4_list, *dns6_list;
	GPtrArray *nbns_list;
	GPtrArray *dns_domains;
	struct in_addr temp_addr;
	int tapdev = -1;
	char **iter;
	int shift = 0;
	gboolean is_restart;
	gboolean has_ip4_prefix = FALSE;
	gboolean has_ip4_address = FALSE;
	gboolean has_ip6_address = FALSE;
	gchar *bus_name = NM_DBUS_SERVICE_OPENVPN;

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	for (i = 1; i < argc; i++) {
		if (!strcmp (argv[i], "--")) {
			i++;
			break;
		}
		if (nm_streq (argv[i], "--debug")) {
			if (i + 2 >= argc) {
				g_printerr ("Missing debug arguments (requires <LEVEL> <PREFIX_TOKEN>)\n");
				exit (1);
			}
			gl.log_level = _nm_utils_ascii_str_to_int64 (argv[++i], 10, 0, LOG_DEBUG, 0);
			gl.log_prefix_token = argv[++i];
		} else if (!strcmp (argv[i], "--tun"))
			tapdev = 0;
		else if (!strcmp (argv[i], "--tap"))
			tapdev = 1;
		else if (!strcmp (argv[i], "--bus-name")) {
			if (++i == argc) {
				g_printerr ("Missing bus name argument\n");
				exit (1);
			}
			if (!g_dbus_is_name (argv[i])) {
				g_printerr ("Invalid bus name\n");
				exit (1);
			}
			bus_name = argv[i];
		} else
			break;
	}
	shift = i - 1;

	if (_LOGD_enabled ()) {
		GString *args;

		args = g_string_new (NULL);
		for (i = 0; i < argc; i++) {
			if (i > 0)
				g_string_append_c (args, ' ');
			if (shift && 1 + shift == i)
				g_string_append (args, "  ");
			tmp = g_strescape (argv[i], NULL);
			g_string_append_printf (args, "\"%s\"", tmp);
			g_free (tmp);
		}

		_LOGD ("command line: %s", args->str);
		g_string_free (args, TRUE);

		for (iter = environ; iter && *iter; iter++)
			_LOGD ("environment: %s", *iter);
	}

	/* shift the arguments to the right leaving only those provided by openvpn */
	argv[shift] = argv[0];
	argv += shift;
	argc -= shift;

	is_restart = argc >= 7 && !g_strcmp0 (argv[6], "restart");

	proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
	                                       G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                                       NULL,
	                                       bus_name,
	                                       NM_VPN_DBUS_PLUGIN_PATH,
	                                       NM_VPN_DBUS_PLUGIN_INTERFACE,
	                                       NULL, &err);
	if (!proxy) {
		_LOGW ("Could not create a D-Bus proxy: %s", err->message);
		g_error_free (err);
		exit (1);
	}

	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_init (&ip4builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_init (&ip6builder, G_VARIANT_TYPE_VARDICT);

	/* External world-visible VPN gateway */
	val = trusted_remote_to_gvariant ();
	if (val)
		g_variant_builder_add (&builder, "{sv}", NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY, val);
	else
		helper_failed (proxy, "VPN Gateway");

	/* Internal VPN subnet gateway */
	tmp = getenv ("route_vpn_gateway");
	val = addr4_to_gvariant (tmp);
	if (val)
		g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_INT_GATEWAY, val);
	else {
		val = addr6_to_gvariant (tmp);
		if (val)
			g_variant_builder_add (&ip6builder, "{sv}", NM_VPN_PLUGIN_IP6_CONFIG_INT_GATEWAY, val);
	}

	/* VPN device */
	tmp = getenv ("dev");
	val = str_to_gvariant (tmp, FALSE);
	if (val)
		g_variant_builder_add (&builder, "{sv}", NM_VPN_PLUGIN_CONFIG_TUNDEV, val);
	else
		helper_failed (proxy, "Tunnel Device");

	if (tapdev == -1)
		tapdev = strncmp (tmp, "tap", 3) == 0;

	/* IPv4 address */
	tmp = getenv ("ifconfig_local");
	if (!tmp && is_restart)
		tmp = argv[4];
	if (tmp && strlen (tmp)) {
		val = addr4_to_gvariant (tmp);
		if (val) {
			has_ip4_address = TRUE;
			g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, val);
		} else
			helper_failed (proxy, "IP4 Address");
	}

	/* PTP address; for vpnc PTP address == internal IP4 address */
	tmp = getenv ("ifconfig_remote");
	if (!tmp && is_restart)
		tmp = argv[5];
	val = addr4_to_gvariant (tmp);
	if (val) {
		/* Sigh.  Openvpn added 'topology' stuff in 2.1 that changes the meaning
		 * of the ifconfig bits without actually telling you what they are
		 * supposed to mean; basically relying on specific 'ifconfig' behavior.
		 */
		if (tmp && !strncmp (tmp, "255.", 4)) {
			guint32 addr;

			/* probably a netmask, not a PTP address; topology == subnet */
			addr = g_variant_get_uint32 (val);
			g_variant_unref (val);
			val = g_variant_new_uint32 (nm_utils_ip4_netmask_to_prefix (addr));
			g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, val);
			has_ip4_prefix = TRUE;
		} else
			g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_PTP, val);
	}

	/* Netmask
	 *
	 * Either TAP or TUN modes can have an arbitrary netmask in newer versions
	 * of openvpn, while in older versions only TAP mode would.  So accept a
	 * netmask if passed, otherwise default to /32 for TUN devices since they
	 * are usually point-to-point.
	 */
	tmp = getenv ("ifconfig_netmask");
	if (tmp && inet_pton (AF_INET, tmp, &temp_addr) > 0) {
		val = g_variant_new_uint32 (nm_utils_ip4_netmask_to_prefix (temp_addr.s_addr));
		g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, val);
	} else if (!tapdev) {
		if (has_ip4_address && !has_ip4_prefix) {
			val = g_variant_new_uint32 (32);
			g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, val);
		}
	} else
		_LOGW ("No IP4 netmask/prefix (missing or invalid 'ifconfig_netmask')");

	val = get_ip4_routes ();
	if (val)
		g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_ROUTES, val);
	else if (is_restart) {
		g_variant_builder_add (&ip4builder, "{sv}",
		                       NM_VPN_PLUGIN_IP4_CONFIG_PRESERVE_ROUTES,
		                       g_variant_new_boolean (TRUE));
	}

	/* IPv6 address */
	tmp = getenv ("ifconfig_ipv6_local");
	if (tmp && strlen (tmp)) {
		val = addr6_to_gvariant (tmp);
		if (val) {
			g_variant_builder_add (&ip6builder, "{sv}", NM_VPN_PLUGIN_IP6_CONFIG_ADDRESS, val);
			has_ip6_address = TRUE;
		} else
			helper_failed (proxy, "IP6 Address");
	}

	/* IPv6 remote address */
	tmp = getenv ("ifconfig_ipv6_remote");
	if (tmp && strlen (tmp)) {
		val = addr6_to_gvariant (tmp);
		if (val)
			g_variant_builder_add (&ip6builder, "{sv}", NM_VPN_PLUGIN_IP6_CONFIG_PTP, val);
		else
			helper_failed (proxy, "IP6 PTP Address");
	}

	/* IPv6 netbits */
	tmp = getenv ("ifconfig_ipv6_netbits");
	if (tmp && strlen (tmp)) {
		long int netbits;

		errno = 0;
		netbits = strtol (tmp, NULL, 10);
		if (errno || netbits < 0 || netbits > 128) {
			_LOGW ("Ignoring invalid prefix '%s'", tmp);
		} else {
			val = g_variant_new_uint32 ((guint32) netbits);
			g_variant_builder_add (&ip6builder, "{sv}", NM_VPN_PLUGIN_IP6_CONFIG_PREFIX, val);
		}
	}

	val = get_ip6_routes ();
	if (val)
		g_variant_builder_add (&ip6builder, "{sv}", NM_VPN_PLUGIN_IP6_CONFIG_ROUTES, val);
	else if (is_restart) {
		g_variant_builder_add (&ip6builder, "{sv}",
		                       NM_VPN_PLUGIN_IP6_CONFIG_PRESERVE_ROUTES,
		                       g_variant_new_boolean (TRUE));
	}

	/* DNS and WINS servers */
	dns_domains = g_ptr_array_sized_new (3);
	dns4_list = g_ptr_array_new ();
	dns6_list = g_ptr_array_new ();
	nbns_list = g_ptr_array_new ();

	for (i = 1; i < 256; i++) {
		char *env_name;

		env_name = g_strdup_printf ("foreign_option_%d", i);
		tmp = getenv (env_name);
		g_free (env_name);

		if (!tmp || strlen (tmp) < 1)
			break;

		if (!g_str_has_prefix (tmp, "dhcp-option "))
			continue;

		tmp += 12; /* strlen ("dhcp-option ") */

		if (g_str_has_prefix (tmp, "DNS "))
			parse_addr_list (dns4_list, dns6_list, tmp + 4);
		else if (g_str_has_prefix (tmp, "WINS "))
			parse_addr_list (nbns_list, NULL, tmp + 5);
		else if (g_str_has_prefix (tmp, "DOMAIN ") && is_domain_valid (tmp + 7))
			g_ptr_array_add (dns_domains, tmp + 7);
	}

	if (dns4_list->len) {
		val = g_variant_new_array (G_VARIANT_TYPE_UINT32, (GVariant **) dns4_list->pdata, dns4_list->len);
		g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_DNS, val);
	}

	if (has_ip6_address && dns6_list->len) {
		val = g_variant_new_array (G_VARIANT_TYPE ("ay"), (GVariant **) dns6_list->pdata, dns6_list->len);
		g_variant_builder_add (&ip6builder, "{sv}", NM_VPN_PLUGIN_IP6_CONFIG_DNS, val);
	}

	if (nbns_list->len) {
		val = g_variant_new_array (G_VARIANT_TYPE_UINT32, (GVariant **) nbns_list->pdata, nbns_list->len);
		g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_NBNS, val);
	}

	if (dns_domains->len) {
		val = g_variant_new_strv ((const gchar **) dns_domains->pdata, dns_domains->len);
		g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_DOMAINS, val);

		/* Domains apply to both IPv4 and IPv6 configurations */
		if (has_ip6_address) {
			val = g_variant_new_strv ((const gchar **) dns_domains->pdata, dns_domains->len);
			g_variant_builder_add (&ip6builder, "{sv}", NM_VPN_PLUGIN_IP6_CONFIG_DOMAINS, val);
		}
	}

	g_ptr_array_unref (dns4_list);
	g_ptr_array_unref (dns6_list);
	g_ptr_array_unref (nbns_list);
	g_ptr_array_unref (dns_domains);

	/* Tunnel MTU */
	tmp = getenv ("tun_mtu");
	if (tmp && tmp[0]) {
		guint32 mtu;

		mtu = _nm_utils_ascii_str_to_int64 (tmp, 10, 0, G_MAXUINT32, 0);
		if (errno)
			_LOGW ("Ignoring invalid tunnel MTU '%s'", tmp);
		else {
			g_variant_builder_add (&builder, "{sv}",
			                       NM_VPN_PLUGIN_CONFIG_MTU,
			                       g_variant_new_uint32 (mtu));
		}
	}

	ip4config = g_variant_builder_end (&ip4builder);

	if (g_variant_n_children (ip4config)) {
		val = g_variant_new_boolean (TRUE);
		g_variant_builder_add (&builder, "{sv}", NM_VPN_PLUGIN_CONFIG_HAS_IP4, val);
	} else {
		g_variant_unref (ip4config);
		ip4config = NULL;
	}

	ip6config = g_variant_builder_end (&ip6builder);

	if (g_variant_n_children (ip6config)) {
		val = g_variant_new_boolean (TRUE);
		g_variant_builder_add (&builder, "{sv}", NM_VPN_PLUGIN_CONFIG_HAS_IP6, val);
	} else {
		g_variant_unref (ip6config);
		ip6config = NULL;
	}

	if (!ip4config && !ip6config)
		helper_failed (proxy, "IPv4 or IPv6 configuration");

	/* Send the config info to nm-openvpn-service */
	send_config (proxy, g_variant_builder_end (&builder), ip4config, ip6config);

	g_object_unref (proxy);

	return 0;
}
