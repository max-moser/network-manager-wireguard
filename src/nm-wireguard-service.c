/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-wireguard-service - wireguard integration with NetworkManager
 *
 * Copyright (C) 2005 - 2008 Tim Niemueller <tim@niemueller.de>
 * Copyright (C) 2005 - 2010 Dan Williams <dcbw@redhat.com>
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
 * $Id: nm-openvpn-service.c 4232 2008-10-29 09:13:40Z tambeti $
 *
 */

#include "nm-default.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <locale.h>
#include <pwd.h>
#include <grp.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <glib-unix.h>

#include "utils.h"
#include "import-export.h"
#include "nm-utils/nm-shared-utils.h"
#include "nm-utils/nm-vpn-plugin-macros.h"

#if !defined(DIST_VERSION)
# define DIST_VERSION VERSION
#endif

#define RUNDIR  LOCALSTATEDIR"/run/NetworkManager"

static struct {
	gboolean debug;
	int log_level;
	int log_level_ovpn;
	bool log_syslog;
	GSList *pids_pending_list;
} gl/*obal*/;

/*****************************************************************************/

#define NM_TYPE_WIREGUARD_PLUGIN            (nm_wireguard_plugin_get_type ())
#define NM_WIREGUARD_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_WIREGUARD_PLUGIN, NMWireguardPlugin))
#define NM_WIREGUARD_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_WIREGUARD_PLUGIN, NMWireguardPluginClass))
#define NM_IS_WIREGUARD_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_WIREGUARD_PLUGIN))
#define NM_IS_WIREGUARD_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_WIREGUARD_PLUGIN))
#define NM_WIREGUARD_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_WIREGUARD_PLUGIN, NMWireguardPluginClass))

typedef struct {
	NMVpnServicePlugin parent;
} NMWireguardPlugin;

typedef struct {
	NMVpnServicePluginClass parent;
} NMWireguardPluginClass;

GType nm_wireguard_plugin_get_type (void);

NMWireguardPlugin *nm_wireguard_plugin_new (const char *bus_name);

/*****************************************************************************/

// this struct is needed for the connect-timer callback (send_configs)
typedef struct _Configs{
	NMVpnServicePlugin *plugin;
	GVariant *config;
	GVariant *ip4config;
	GVariant *ip6config;
	GVariant *dns_config;
} Configs;

typedef struct {
	gboolean interactive;
	char *mgt_path;
	char *connection_file;
	GString *connection_config;
} NMWireguardPluginPrivate;

G_DEFINE_TYPE (NMWireguardPlugin, nm_wireguard_plugin, NM_TYPE_VPN_SERVICE_PLUGIN)

#define NM_WIREGUARD_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_WIREGUARD_PLUGIN, NMWireguardPluginPrivate))

/*****************************************************************************/

#define _NMLOG(level, ...) \
	G_STMT_START { \
		if (gl.log_level >= (level)) { \
			g_print ("nm-wireguard[%ld] %-7s " _NM_UTILS_MACRO_FIRST (__VA_ARGS__) "\n", \
			         (long) getpid (), \
			         nm_utils_syslog_to_str (level) \
			         _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
		} \
	} G_STMT_END

static gboolean
_LOGD_enabled (void)
{
	return gl.log_level >= LOG_INFO;
}

#define _LOGD(...) _NMLOG(LOG_INFO,    __VA_ARGS__)
#define _LOGI(...) _NMLOG(LOG_NOTICE,  __VA_ARGS__)
#define _LOGW(...) _NMLOG(LOG_WARNING, __VA_ARGS__)

/*****************************************************************************/

static const char *
wg_quick_find_exepath (void)
{
	static const char *paths[] = {
		"/usr/sbin/wg-quick",
		"/usr/bin/wg-quick",
		"/sbin/wg-quick",
		"/bin/wg-quick",
		"/usr/local/sbin/wg-quick",
		"/usr/local/bin/wg-quick",
	};
	int i;

	for (i = 0; i < G_N_ELEMENTS(paths); i++) {
		if (g_file_test (paths[i], G_FILE_TEST_EXISTS)) {
			return paths[i];
		}
	}

	return NULL;
}

// create a valid interface name from the specified string
// this allocates memory which should be freed after usage
//
// wg-quick uses the following regular expression to check the interface name
// for validity:
// [a-zA-Z0-9_=+.-]{1,15}
static gchar *
create_interface_name_from_string(const char *str)
{
	int i;
	int len = MIN(strlen(str), 15);
	char ch;
	gchar *interface_name = g_strndup(str, len);

	for(i = 0; i < len; i++){
		ch = interface_name[i];
		if(!g_ascii_isalnum(ch) &&
			(ch != '_') &&
			(ch != '=') &&
			(ch != '+') &&
			(ch != '.') &&
			(ch != '-')){

				// if we come across an invalid character, let's replace it with '-'
				interface_name[i] = '-';
			}
	}

	return interface_name;
}

/*****************************************************************************/

// disconnect from the current connection
static gboolean
wg_disconnect(NMVpnServicePlugin *plugin,
				GError **error)
{
	NMWireguardPluginPrivate *priv = NM_WIREGUARD_PLUGIN_GET_PRIVATE(plugin);
	const char *wg_quick_path = wg_quick_find_exepath();
	char *filename = priv->connection_file;
	GString *cfg_content = priv->connection_config;
	char *command;
	int retcode = 1;

	if(wg_quick_path == NULL){
		_LOGW("Error: Could not find wg-quick!");
		return FALSE;
	}

	if(!filename || !cfg_content){
		_LOGW("Error: Cannot remember the connection details for Disconnect");
		g_set_error_literal(error,
							NM_VPN_PLUGIN_ERROR,
							NM_VPN_PLUGIN_ERROR_FAILED,
							"Cannot remember the connection details for Disconnect");
		return FALSE;
	}

	// create the temporary configuration file
	g_file_set_contents(filename, cfg_content->str, cfg_content->len, error);
	g_chmod(filename, 0400);

	// join together our command
	command = g_strdup_printf("%s down '%s'", wg_quick_path, filename);

	if(!g_spawn_command_line_sync(command, NULL, NULL, &retcode, error)){
		_LOGW("An error occured while spawning wg-quick! (Error: %s)", (*error)->message);
	}

	// delete the file and free temporary private data
	g_remove(filename);
	g_free(command);
	g_string_free(priv->connection_config, TRUE);
	g_free(priv->connection_file);
	priv->connection_config = NULL;
	priv->connection_file = NULL;

	_LOGI("Disconnected from Wireguard Connection!");
	return TRUE;
}

// get the setting from the NMSettingVpn if it is set and not empty (or NULL otherwise)
static const gchar *
get_setting(NMSettingVpn *s_vpn, const char *key)
{
	const gchar *setting = nm_setting_vpn_get_data_item(s_vpn, key);

	if(!setting || !setting[0]){
		return NULL;
	}

	return setting;
}

// create a GVariant as expected by SetIp4Config() from the IP4 string
static GVariant *
ip4_to_gvariant (const char *str)
{
	gchar *addr;
	gchar **tmp, **tmp2;
	struct in_addr temp_addr;
	GVariant *res;

	/* Empty */
	if (!str || strlen (str) < 1){
		return NULL;
	}

	// strip the port and subnet
	tmp = g_strsplit(str, "/", 0);
	tmp2 = g_strsplit(tmp[0], ":", 0);
	addr = g_strdup(tmp[0]);

	if (inet_pton (AF_INET, addr, &temp_addr) <= 0){
		res = NULL;;
	}
	else{
		res = g_variant_new_uint32 (temp_addr.s_addr);
	}
	
	g_strfreev(tmp);
	g_strfreev(tmp2);
	g_free(addr);

	return res;
}

// same as above, but for IP6
static GVariant *
ip6_to_gvariant (const char *str)
{
	struct in6_addr temp_addr;
	gchar *addr;
	gchar **tmp;
	GVariantBuilder builder;
	int i;

	/* Empty */
	if (!str || strlen (str) < 1){
		return NULL;
	}

	// since we accept a subnet at the end, let's do away with that.
	tmp = g_strsplit(str, "/", 0);
	addr = g_strdup(tmp[0]);
	g_strfreev(tmp);

	if (inet_pton (AF_INET6, addr, &temp_addr) <= 0){
		return NULL;
	}

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("ay"));
	for (i = 0; i < sizeof (temp_addr); i++){
		g_variant_builder_add (&builder, "y", ((guint8 *) &temp_addr)[i]);
	}

	return g_variant_builder_end (&builder);
}

// callback for the timer started after the configuration
// this is necessary because:
// * NetworkManager expects the functions SetConfig(), SetIp4Config() and SetIp6Config()
//   to be called before it considers a VPN connection to be started
// * the above functions cannot be called from within Connect() and ConnectInteractively()
//   directly, because they would get blocked until after the connection timeout has completed
//   (and thus, the connection be considered to have failed)
static gboolean
send_config(gpointer data)
{
	Configs *cfgs = data;

	nm_vpn_service_plugin_set_config(cfgs->plugin, cfgs->config);							

	if(cfgs->ip4config){
		nm_vpn_service_plugin_set_ip4_config(cfgs->plugin, cfgs->ip4config);
	}

	if(cfgs->ip6config){
		nm_vpn_service_plugin_set_ip6_config(cfgs->plugin, cfgs->ip6config);
	}

	// if we don't return FALSE, it's gonna get called again and again and again and...
	return FALSE;
}

// create a Config, Ip4Config and Ip6Config from the specified NMVpnServicePlugin and NMConnection
// and create a timer that sends the configuration to the plugin (see 'send_config()' above)
static gboolean
set_config(NMVpnServicePlugin *plugin, NMConnection *connection)
{
	NMSettingVpn *s_vpn = nm_connection_get_setting_vpn(connection);
	GVariantBuilder builder, ip4builder, ip6builder;
	GVariantBuilder dns_builder;
	GVariant *config, *ip4config, *ip6config, *dns_config;
	GVariant *val;
	const char *setting;
	const gchar *if_name;
	guint64 subnet = 24;
	gboolean has_ip4 = FALSE;
	gboolean has_ip6 = FALSE;
	gboolean has_dns = FALSE;
	Configs *configs = malloc(sizeof(Configs));
	memset(configs, 0, sizeof(Configs));

	// get ready to build the IP4 stuff and send it
	// (required that the connection does not time-out)
	g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_init(&ip4builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_init(&ip6builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_init(&dns_builder, G_VARIANT_TYPE_VARDICT);

	// build the configs
	setting = get_setting(s_vpn, NM_WG_KEY_ADDR_IP4);
	if(setting){
		val = ip4_to_gvariant(setting);
		if(val){
			g_variant_builder_add(&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, val);

			// try to find the subnet from the IP
			if(g_strrstr(setting, "/")){
				gchar **tmp;
				tmp = g_strsplit(setting, "/", 2);
				if(!g_ascii_string_to_unsigned(tmp[1], 10, 0, 32, &subnet, NULL)){
					subnet = 24;
				}
				g_strfreev(tmp);
			}
			val = g_variant_new_uint32((guint32)subnet);
			g_variant_builder_add(&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, val);
			has_ip4 = TRUE;
		}
	}

	setting = get_setting(s_vpn, NM_WG_KEY_DNS);
	if(setting){
		// TODO
		val = g_variant_new_string(setting);
		g_variant_builder_add(&dns_builder, "{ss}", NMV_WG_TAG_DNS, val);
		has_dns = TRUE;
	}

	setting = get_setting(s_vpn, NM_WG_KEY_ENDPOINT);
	if(setting){
		// TODO
	}

	setting = get_setting(s_vpn, NM_WG_KEY_MTU);
	if(setting){
		guint64 mtu = 1420;
		if(!g_ascii_string_to_unsigned(setting, 10, 0, 1500, &mtu, NULL)){
			mtu = 1420;
		}
		val = g_variant_new_uint32(mtu);
		g_variant_builder_add(&builder, "{sv}", NM_VPN_PLUGIN_CONFIG_MTU, val);
		g_variant_builder_add(&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_MTU, val);
	}

	// keep NM from creating a default route to the interface which screws up the entire routing
	// (we already did this ourselves)
	val = g_variant_new_boolean(TRUE);
	g_variant_builder_add(&builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_NEVER_DEFAULT, val);
	g_variant_builder_add(&builder, "{sv}", NM_VPN_PLUGIN_IP6_CONFIG_NEVER_DEFAULT, val);
	g_variant_builder_add(&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_NEVER_DEFAULT, val);
	g_variant_builder_add(&ip6builder, "{sv}", NM_VPN_PLUGIN_IP6_CONFIG_NEVER_DEFAULT, val);

	if_name = create_interface_name_from_string(nm_connection_get_id(connection));
	val = g_variant_new_string(if_name);
	g_variant_builder_add(&builder, "{sv}", NM_VPN_PLUGIN_CONFIG_TUNDEV, val);
	g_variant_builder_add(&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV, val);
	g_free((gchar *)if_name);

	setting = get_setting(s_vpn, NM_WG_KEY_ADDR_IP6);
	if(setting){
		val = ip6_to_gvariant(setting);
		if(val){
			g_variant_builder_add(&ip6builder, "{sv}", NM_VPN_PLUGIN_IP6_CONFIG_ADDRESS, val);
			has_ip6 = TRUE;
		}
	}

	// check if we have any of IP4 or IP6 and if so, include them in the config
	if(!has_ip4 && !has_ip6){
		return FALSE;
	}

	if(has_ip4){
		val = g_variant_new_boolean(TRUE);
		g_variant_builder_add(&builder, "{sv}", NM_VPN_PLUGIN_CONFIG_HAS_IP4, val);
	}

	if(has_ip6){
		val = g_variant_new_boolean(TRUE);
		g_variant_builder_add(&builder, "{sv}", NM_VPN_PLUGIN_CONFIG_HAS_IP6, val);
	}

	// finish the builders
	config = g_variant_builder_end(&builder);
	ip4config = g_variant_builder_end(&ip4builder);
	ip6config = g_variant_builder_end(&ip6builder);
	dns_config = g_variant_builder_end(&dns_builder);

	// populate the configs struct and send the configuration asynchronously
	configs->ip4config = (has_ip4) ? ip4config : NULL;
	configs->ip6config = (has_ip6) ? ip6config : NULL;
	configs->dns_config = (has_dns) ? dns_config : NULL;
	configs->plugin    = plugin;
	configs->config    = config;
	g_timeout_add(0, send_config, configs);

	return TRUE;
}

// the common part of both Connect() and ConnectInteractively():
// create a configuration string from the NMVpnServicePlugin and NMConnection,
// export this configuration to a temporary file (/tmp/CONNECTION-ID.conf)
// and call wg-quick on this script
// the temporary file gets deleted immediately after wg-quick has completed
// 
// in order to be able to disconnect properly, the configuration string
// and filename are saved in the plugin's private data, such that the
// temporary file can be re-created in the Disconnect() method
static gboolean
connect_common(NMVpnServicePlugin *plugin,
				NMConnection *connection,
				GVariant *details,
				GError **error)
{
	NMWireguardPluginPrivate *priv = NM_WIREGUARD_PLUGIN_GET_PRIVATE(plugin);
	const char *wg_quick_path = wg_quick_find_exepath();
	const char *connection_name = nm_connection_get_id(connection);
	const gchar *if_name = create_interface_name_from_string(connection_name);
	char *command;
	int retcode = 1;
	char *filename = NULL;
	GString *connection_config = NULL;

	_LOGI("Setting up Wireguard Connection ('%s')", connection_name);
	if(wg_quick_path == NULL){
		_LOGW("Error: Could not find wg-quick!");
		return FALSE;
	}

	// take the connection details and create the configuration string from it
	connection_config = create_config_string(connection, error);
	if(!connection_config){
		_LOGW("Error: Could not create configuration for connection '%s'!", connection_name);
		g_set_error_literal(error,
							NM_VPN_PLUGIN_ERROR,
							NM_VPN_PLUGIN_ERROR_FAILED,
							"Could not create configuration from connection");
		return FALSE;
	}
	priv->connection_config = connection_config;
	filename = g_strdup_printf("/tmp/%s.conf", if_name);
	priv->connection_file = filename;

	if(!do_export(filename, connection, error)){
		_LOGW("Error: Could not create temporary configuration file for connection '%s'", connection_name);
		return FALSE;
	}
	g_chmod(filename, 0400);

	// join together our command
	command = g_strdup_printf("%s up '%s'", wg_quick_path, filename);

	if(!g_spawn_command_line_sync(command, NULL, NULL, &retcode, error)){
		_LOGW("An error occured while spawning wg-quick! (Error: %s)", (*error)->message);
		return FALSE;
	}

	// remove the file and free the command string
	g_remove(filename);
	g_free(command);
	g_free((gchar *)if_name);

	set_config(plugin, connection);

	return TRUE;
}

// non-interactive connect
// this version of connect is not allowed to ask the user for secrets, etc. interactively!
static gboolean
wg_connect (NMVpnServicePlugin *plugin,
				NMConnection *connection,
				GError **error)
{
	_LOGI("Connecting to Wireguard: '%s'", nm_connection_get_id(connection));
	return connect_common(plugin, connection, NULL, error);
}

// interactive connect (allows for user interaction)
// this is the function that is actually called when the user clicks the connection in the GUI
static gboolean
wg_connect_interactive(NMVpnServicePlugin *plugin,
							NMConnection *connection,
							GVariant *details,
							GError **error)
{
	_LOGI("Connecting interactively to Wireguard: '%s'", nm_connection_get_id(connection));
	if(!connect_common(plugin, connection, details, error)){
		return FALSE;
	}

	NM_WIREGUARD_PLUGIN_GET_PRIVATE(plugin)->interactive = TRUE;
	return TRUE;
}

// can't really tell what secrets we need: just assume that we don't need any
static gboolean
wg_need_secrets (NMVpnServicePlugin *plugin,
					NMConnection *connection,
					const char **setting_name,
					GError **error)
{
	return FALSE;
}


// should be fine
static gboolean
wg_new_secrets (NMVpnServicePlugin *plugin,
                  NMConnection *connection,
				  GError **error)
{
	return TRUE;
}

static void
nm_wireguard_plugin_init (NMWireguardPlugin *plugin)
{
}

static void
dispose (GObject *object)
{
	G_OBJECT_CLASS (nm_wireguard_plugin_parent_class)->dispose (object);
}

static void
nm_wireguard_plugin_class_init (NMWireguardPluginClass *plugin_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (plugin_class);
	NMVpnServicePluginClass *parent_class = NM_VPN_SERVICE_PLUGIN_CLASS (plugin_class);

	g_type_class_add_private (object_class, sizeof (NMWireguardPluginPrivate));

	object_class->dispose = dispose;

	/* virtual methods */
	parent_class->connect             = wg_connect;
	parent_class->connect_interactive = wg_connect_interactive;
	parent_class->need_secrets        = wg_need_secrets;
	parent_class->disconnect          = wg_disconnect;
	parent_class->new_secrets         = wg_new_secrets;
}

NMWireguardPlugin *
nm_wireguard_plugin_new (const char *bus_name)
{
	NMWireguardPlugin *plugin;
	GError *error = NULL;

	// NOTE: owning this name must be allowed in a DBUS configuration file:
	// "/etc/dbus-1/system.d/nm-wireguard-service.conf"
	// (an example conf file was copied to the root of this project)
	plugin =  (NMWireguardPlugin *) g_initable_new (NM_TYPE_WIREGUARD_PLUGIN, NULL, &error,
	                                              NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME, bus_name,
	                                              NM_VPN_SERVICE_PLUGIN_DBUS_WATCH_PEER, !gl.debug,
	                                              NULL);


	if(!plugin) {
		_LOGW ("Failed to initialize a plugin instance: %s", error->message);
		g_error_free (error);
	}

	return plugin;
}

static gboolean
signal_handler (gpointer user_data)
{
	g_main_loop_quit (user_data);
	return G_SOURCE_REMOVE;
}

static void
quit_mainloop (NMVpnServicePlugin *plugin, gpointer user_data)
{
	g_main_loop_quit ((GMainLoop *) user_data);
}

int
main (int argc, char *argv[])
{
	NMWireguardPlugin *plugin;
	gboolean persist = FALSE;
	GOptionContext *opt_ctx = NULL;
	gchar *bus_name = NM_DBUS_SERVICE_WIREGUARD;
	GError *error = NULL;
	GMainLoop *loop;

	GOptionEntry options[] = {
		{ "persist", 0, 0, G_OPTION_ARG_NONE, &persist, N_("Don’t quit when VPN connection terminates"), NULL },
		{ "debug", 0, 0, G_OPTION_ARG_NONE, &gl.debug, N_("Enable verbose debug logging (may expose passwords)"), NULL },
		{ "bus-name", 0, 0, G_OPTION_ARG_STRING, &bus_name, N_("D-Bus name to use for this instance"), NULL },
		{NULL}
	};

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	if (getenv ("WIREGUARD_DEBUG")){
		gl.debug = TRUE;
	}

	/* locale will be set according to environment LC_* variables */
	setlocale (LC_ALL, "");

	bindtextdomain (GETTEXT_PACKAGE, NM_WIREGUARD_LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	/* Parse options */
	opt_ctx = g_option_context_new (NULL);
	g_option_context_set_translation_domain (opt_ctx, GETTEXT_PACKAGE);
	g_option_context_set_ignore_unknown_options (opt_ctx, FALSE);
	g_option_context_set_help_enabled (opt_ctx, TRUE);
	g_option_context_add_main_entries (opt_ctx, options, NULL);

	g_option_context_set_summary (opt_ctx,
	                              "nm-wireguard-service provides integrated Wireguard capability to NetworkManager.");

	if (!g_option_context_parse (opt_ctx, &argc, &argv, &error)) {
		g_printerr ("Error parsing the command line options: %s\n", error->message);
		g_option_context_free (opt_ctx);
		g_clear_error (&error);
		exit (1);
	}
	g_option_context_free (opt_ctx);

	gl.log_level = _nm_utils_ascii_str_to_int64 (getenv ("NM_VPN_LOG_LEVEL"),
	                                             10, 0, LOG_DEBUG, -1);
	if (gl.log_level >= 0) {
		if (gl.log_level >= LOG_DEBUG)
			gl.log_level_ovpn = 10;
		else if (gl.log_level >= LOG_INFO)
			gl.log_level_ovpn = 5;
		else if (gl.log_level > 0)
			gl.log_level_ovpn = 2;
		else
			gl.log_level_ovpn = 1;
	} else if (gl.debug)
		gl.log_level_ovpn = 10;
	else {
		/* the default level is already "--verb 1", which is fine for us. */
		gl.log_level_ovpn = -1;
	}

	if (gl.log_level < 0)
		gl.log_level = gl.debug ? LOG_INFO : LOG_NOTICE;

	gl.log_syslog = _nm_utils_ascii_str_to_int64 (getenv ("NM_VPN_LOG_SYSLOG"),
	                                              10, 0, 1,
	                                              gl.debug ? 0 : 1);

	_LOGD ("nm-wireguard-service (version " DIST_VERSION ") starting...");

	// this is left over from openvpn, and doesn't seem to bother us...
	if (   !g_file_test ("/sys/class/misc/tun", G_FILE_TEST_EXISTS)
	    && (system ("/sbin/modprobe tun") == -1)){
			exit (EXIT_FAILURE);
		}

	// here, the plugin is initialised
	// (and the D-BUS thing is created: be careful that you're actually allowed to use the name!)
	plugin = nm_wireguard_plugin_new (bus_name);
	if (!plugin){
		exit (EXIT_FAILURE);
	}

	loop = g_main_loop_new (NULL, FALSE);

	if (!persist)
		g_signal_connect (plugin, "quit", G_CALLBACK (quit_mainloop), loop);

	signal (SIGPIPE, SIG_IGN);
	g_unix_signal_add (SIGTERM, signal_handler, loop);
	g_unix_signal_add (SIGINT, signal_handler, loop);

	// run the main loop
	g_main_loop_run (loop);

	// when the main loop has finsihed (be it through a signal or whatever)
	// the plugin gets shut down
	g_object_unref (plugin);
	g_main_loop_unref (loop);

	exit (EXIT_SUCCESS);
}
