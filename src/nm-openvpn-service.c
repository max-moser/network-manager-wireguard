/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-openvpn-service - openvpn integration with NetworkManager
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
#include <glib-unix.h>

#include "utils.h"
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

#define NM_OPENVPN_HELPER_PATH LIBEXECDIR"/nm-openvpn-service-openvpn-helper"

/*****************************************************************************/

#define NM_TYPE_OPENVPN_PLUGIN            (nm_openvpn_plugin_get_type ())
#define NM_OPENVPN_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_OPENVPN_PLUGIN, NMOpenvpnPlugin))
#define NM_OPENVPN_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_OPENVPN_PLUGIN, NMOpenvpnPluginClass))
#define NM_IS_OPENVPN_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_OPENVPN_PLUGIN))
#define NM_IS_OPENVPN_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_OPENVPN_PLUGIN))
#define NM_OPENVPN_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_OPENVPN_PLUGIN, NMOpenvpnPluginClass))

typedef struct {
	NMVpnServicePlugin parent;
} NMOpenvpnPlugin;

typedef struct {
	NMVpnServicePluginClass parent;
} NMOpenvpnPluginClass;

GType nm_openvpn_plugin_get_type (void);

NMOpenvpnPlugin *nm_openvpn_plugin_new (const char *bus_name);

/*****************************************************************************/

typedef enum {
	OPENVPN_BINARY_VERSION_INVALID,
	OPENVPN_BINARY_VERSION_UNKNOWN,
	OPENVPN_BINARY_VERSION_2_3_OR_OLDER,
	OPENVPN_BINARY_VERSION_2_4_OR_NEWER,
} OpenvpnBinaryVersion;

typedef struct {
	GPid pid;
	guint watch_id;
	guint kill_id;
	NMOpenvpnPlugin *plugin;
} PidsPendingData;

typedef struct {
	char *default_username;
	char *username;
	char *password;
	char *priv_key_pass;
	char *proxy_username;
	char *proxy_password;
	char *pending_auth;
	char *challenge_state_id;
	char *challenge_text;
	GIOChannel *socket_channel;
	guint socket_channel_eventid;
} NMOpenvpnPluginIOData;

typedef struct {
	GPid pid;
	guint connect_timer;
	guint connect_count;
	NMOpenvpnPluginIOData *io_data;
	gboolean interactive;
	char *mgt_path;
} NMOpenvpnPluginPrivate;

G_DEFINE_TYPE (NMOpenvpnPlugin, nm_openvpn_plugin, NM_TYPE_VPN_SERVICE_PLUGIN)

#define NM_OPENVPN_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_OPENVPN_PLUGIN, NMOpenvpnPluginPrivate))

/*****************************************************************************/

typedef struct {
	const char *name;
	GType type;
	gint int_min;
	gint int_max;
	gboolean address;
} ValidProperty;

static const ValidProperty valid_properties[] = {
	{ NM_OPENVPN_KEY_AUTH,                 G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_CA,                   G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_CERT,                 G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_CIPHER,               G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_KEYSIZE,              G_TYPE_INT, 1, 65535, FALSE },
	{ NM_OPENVPN_KEY_COMP_LZO,             G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_CONNECTION_TYPE,      G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_FLOAT,                G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_FRAGMENT_SIZE,        G_TYPE_INT, 0, G_MAXINT, FALSE },
	{ NM_OPENVPN_KEY_KEY,                  G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_LOCAL_IP,             G_TYPE_STRING, 0, 0, TRUE },
	{ NM_OPENVPN_KEY_MSSFIX,               G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_MTU_DISC,             G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_PING,                 G_TYPE_INT, 0, G_MAXINT, FALSE },
	{ NM_OPENVPN_KEY_PING_EXIT,            G_TYPE_INT, 0, G_MAXINT, FALSE },
	{ NM_OPENVPN_KEY_PING_RESTART,         G_TYPE_INT, 0, G_MAXINT, FALSE },
	{ NM_OPENVPN_KEY_MAX_ROUTES,           G_TYPE_INT, 0, 100000000, FALSE },
	{ NM_OPENVPN_KEY_PROTO_TCP,            G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_PORT,                 G_TYPE_INT, 1, 65535, FALSE },
	{ NM_OPENVPN_KEY_PROXY_TYPE,           G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_PROXY_SERVER,         G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_PROXY_PORT,           G_TYPE_INT, 1, 65535, FALSE },
	{ NM_OPENVPN_KEY_PROXY_RETRY,          G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_HTTP_PROXY_USERNAME,  G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_REMOTE,               G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_REMOTE_RANDOM,        G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_REMOTE_IP,            G_TYPE_STRING, 0, 0, TRUE },
	{ NM_OPENVPN_KEY_RENEG_SECONDS,        G_TYPE_INT, 0, G_MAXINT, FALSE },
	{ NM_OPENVPN_KEY_STATIC_KEY,           G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, G_TYPE_INT, 0, 1, FALSE },
	{ NM_OPENVPN_KEY_TA,                   G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_TA_DIR,               G_TYPE_INT, 0, 1, FALSE },
	{ NM_OPENVPN_KEY_TAP_DEV,              G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_DEV,                  G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_DEV_TYPE,             G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_TUN_IPV6,             G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_TLS_CIPHER,           G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_TLS_CRYPT,            G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_TLS_REMOTE,           G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_VERIFY_X509_NAME,     G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_REMOTE_CERT_TLS,      G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_NS_CERT_TYPE,         G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_TUNNEL_MTU,           G_TYPE_INT, 0, G_MAXINT, FALSE },
	{ NM_OPENVPN_KEY_USERNAME,             G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_PASSWORD"-flags",     G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_CERTPASS"-flags",     G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_NOSECRET,             G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD"-flags", G_TYPE_STRING, 0, 0, FALSE },
	{ NULL,                                G_TYPE_NONE, FALSE }
};

static const ValidProperty valid_secrets[] = {
	{ NM_OPENVPN_KEY_PASSWORD,             G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_CERTPASS,             G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_NOSECRET,             G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD,  G_TYPE_STRING, 0, 0, FALSE },
	{ NULL,                                G_TYPE_NONE, FALSE }
};

/*****************************************************************************/

#define _NMLOG(level, ...) \
	G_STMT_START { \
		if (gl.log_level >= (level)) { \
			g_print ("nm-openvpn[%ld] %-7s " _NM_UTILS_MACRO_FIRST (__VA_ARGS__) "\n", \
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
openvpn_binary_find_exepath (void)
{
	static const char *paths[] = {
		"/usr/sbin/openvpn",
		"/sbin/openvpn",
		"/usr/local/sbin/openvpn",
	};
	int i;

	for (i = 0; i < G_N_ELEMENTS (paths); i++) {
		if (g_file_test (paths[i], G_FILE_TEST_EXISTS))
			return paths[i];
	}
	return NULL;
}

static OpenvpnBinaryVersion
openvpn_binary_detect_version (const char *exepath)
{
	gs_free char *s_stdout = NULL;
	const char *s;
	int exit_code;
	int n;

	g_return_val_if_fail (exepath && exepath[0] == '/', OPENVPN_BINARY_VERSION_UNKNOWN);

	if (!g_spawn_sync (NULL,
	                   (char *[]) { (char *) exepath, "--version", NULL },
	                   NULL,
	                   G_SPAWN_STDERR_TO_DEV_NULL,
	                   NULL,
	                   NULL,
	                   &s_stdout,
	                   NULL,
	                   &exit_code,
	                   NULL))
		return OPENVPN_BINARY_VERSION_UNKNOWN;

	if (   !WIFEXITED (exit_code)
	    || WEXITSTATUS (exit_code) != 1) {
		/* expect return code 1 (OPENVPN_EXIT_STATUS_USAGE) */
		return OPENVPN_BINARY_VERSION_UNKNOWN;
	}

	/* the output for --version starts with title_string, which starts with PACKAGE_STRING,
	 * which looks like "OpenVPN 2.#...". Do a strict parsing here... */
	if (   !s_stdout
	    || !g_str_has_prefix (s_stdout, "OpenVPN 2."))
		return OPENVPN_BINARY_VERSION_UNKNOWN;
	s = &s_stdout[NM_STRLEN ("OpenVPN 2.")];

	if (!g_ascii_isdigit (s[0]))
		return OPENVPN_BINARY_VERSION_UNKNOWN;

	n = 0;
	do {
		if (n > G_MAXINT / 100)
			return OPENVPN_BINARY_VERSION_UNKNOWN;
		n = (n * 10) + (s[0] - '0');
	} while (g_ascii_isdigit ((++s)[0]));

	if (n <= 3)
		return OPENVPN_BINARY_VERSION_2_3_OR_OLDER;
	return OPENVPN_BINARY_VERSION_2_4_OR_NEWER;
}

static OpenvpnBinaryVersion
openvpn_binary_detect_version_cached (const char *exepath, OpenvpnBinaryVersion *cached)
{
	if (G_UNLIKELY (*cached == OPENVPN_BINARY_VERSION_INVALID))
		*cached = openvpn_binary_detect_version (exepath);
	return *cached;
}

/*****************************************************************************/

static void
pids_pending_data_free (PidsPendingData *pid_data)
{
	nm_clear_g_source (&pid_data->watch_id);
	nm_clear_g_source (&pid_data->kill_id);
	if (pid_data->plugin)
		g_object_remove_weak_pointer ((GObject *) pid_data->plugin, (gpointer *) &pid_data->plugin);
	g_slice_free (PidsPendingData, pid_data);
}

static PidsPendingData *
pids_pending_get (GPid pid)
{
	GSList *iter;

	for (iter = gl.pids_pending_list; iter; iter = iter->next) {
		if (((PidsPendingData *) iter->data)->pid == pid)
			return iter->data;
	}
	g_return_val_if_reached (NULL);
}

static void openvpn_child_terminated (NMOpenvpnPlugin *plugin, GPid pid, gint status);

static void
pids_pending_child_watch_cb (GPid pid, gint status, gpointer user_data)
{
	PidsPendingData *pid_data = user_data;
	NMOpenvpnPlugin *plugin;

	if (WIFEXITED (status)) {
		int exit_status;

		exit_status = WEXITSTATUS (status);
		if (exit_status != 0)
			_LOGW ("openvpn[%ld] exited with error code %d", (long) pid, exit_status);
		else
			_LOGI ("openvpn[%ld] exited with success", (long) pid);
	}
	else if (WIFSTOPPED (status))
		_LOGW ("openvpn[%ld] stopped unexpectedly with signal %d", (long) pid, WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		_LOGW ("openvpn[%ld] died with signal %d", (long) pid, WTERMSIG (status));
	else
		_LOGW ("openvpn[%ld] died from an unnatural cause", (long) pid);

	g_return_if_fail (pid_data);
	g_return_if_fail (pid_data->pid == pid);
	g_return_if_fail (g_slist_find (gl.pids_pending_list, pid_data));

	plugin = pid_data->plugin;

	pid_data->watch_id = 0;
	gl.pids_pending_list = g_slist_remove (gl.pids_pending_list , pid_data);
	pids_pending_data_free (pid_data);

	if (plugin)
		openvpn_child_terminated (plugin, pid, status);
}

static void
pids_pending_add (GPid pid, NMOpenvpnPlugin *plugin)
{
	PidsPendingData *pid_data;

	g_return_if_fail (NM_IS_OPENVPN_PLUGIN (plugin));
	g_return_if_fail (pid > 0);

	_LOGI ("openvpn[%ld] started", (long) pid);

	pid_data = g_slice_new (PidsPendingData);
	pid_data->pid = pid;
	pid_data->kill_id = 0;
	pid_data->watch_id = g_child_watch_add (pid, pids_pending_child_watch_cb, pid_data);
	pid_data->plugin = plugin;
	g_object_add_weak_pointer ((GObject *) plugin, (gpointer *) &pid_data->plugin);

	gl.pids_pending_list = g_slist_prepend (gl.pids_pending_list, pid_data);
}

static gboolean
pids_pending_ensure_killed (gpointer user_data)
{
	PidsPendingData *pid_data = user_data;

	g_return_val_if_fail (pid_data && pid_data == pids_pending_get (pid_data->pid), FALSE);

	_LOGI ("openvpn[%ld]: send SIGKILL", (long) pid_data->pid);

	pid_data->kill_id = 0;
	kill (pid_data->pid, SIGKILL);
	return FALSE;
}

static void
pids_pending_send_sigterm (GPid pid)
{
	PidsPendingData *pid_data;

	pid_data = pids_pending_get (pid);
	g_return_if_fail (pid_data);

	_LOGI ("openvpn[%ld]: send SIGTERM", (long) pid);

	kill (pid, SIGTERM);
	pid_data->kill_id = g_timeout_add (2000, pids_pending_ensure_killed, pid_data);
}

static void
pids_pending_wait_for_processes (GMainLoop *main_loop)
{
	if (gl.pids_pending_list) {
		_LOGI ("wait for %u openvpn processes to terminate...", g_slist_length (gl.pids_pending_list));

		do {
			g_main_context_iteration (g_main_loop_get_context (main_loop), TRUE);
		} while (gl.pids_pending_list);
	}
}

/*****************************************************************************/

static gboolean
validate_address (const char *address)
{
	const char *p = address;

	if (!address || !strlen (address))
		return FALSE;

	/* Ensure it's a valid DNS name or IP address */
	while (*p) {
		if (!isalnum (*p) && (*p != '-') && (*p != '.'))
			return FALSE;
		p++;
	}
	return TRUE;
}

typedef struct ValidateInfo {
	const ValidProperty *table;
	GError **error;
	gboolean have_items;
} ValidateInfo;

static void
validate_one_property (const char *key, const char *value, gpointer user_data)
{
	ValidateInfo *info = (ValidateInfo *) user_data;
	int i;

	if (*(info->error))
		return;

	info->have_items = TRUE;

	/* 'name' is the setting name; always allowed but unused */
	if (!strcmp (key, NM_SETTING_NAME))
		return;

	for (i = 0; info->table[i].name; i++) {
		const ValidProperty *prop = &info->table[i];
		long int tmp;

		if (strcmp (prop->name, key))
			continue;

		switch (prop->type) {
		case G_TYPE_STRING:
			if (!prop->address || validate_address (value))
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("invalid address “%s”"),
			             key);
			break;
		case G_TYPE_INT:
			errno = 0;
			tmp = strtol (value, NULL, 10);
			if (errno == 0 && tmp >= prop->int_min && tmp <= prop->int_max)
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("invalid integer property “%s” or out of range [%d -> %d]"),
			             key, prop->int_min, prop->int_max);
			break;
		case G_TYPE_BOOLEAN:
			if (!strcmp (value, "yes") || !strcmp (value, "no"))
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             /* Translators: keep "yes" and "no" untranslated! */
			             _("invalid boolean property “%s” (not yes or no)"),
			             key);
			break;
		default:
			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("unhandled property “%s” type %s"),
			             key, g_type_name (prop->type));
			break;
		}
	}

	/* Did not find the property from valid_properties or the type did not match */
	if (!info->table[i].name) {
		g_set_error (info->error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             _("property “%s” invalid or not supported"),
		             key);
	}
}

static gboolean
nm_openvpn_properties_validate (NMSettingVpn *s_vpn, GError **error)
{
	GError *validate_error = NULL;
	ValidateInfo info = { &valid_properties[0], &validate_error, FALSE };

	nm_setting_vpn_foreach_data_item (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		                     _("No VPN configuration options."));
		return FALSE;
	}

	if (validate_error) {
		*error = validate_error;
		return FALSE;
	}
	return TRUE;
}

static gboolean
nm_openvpn_secrets_validate (NMSettingVpn *s_vpn, GError **error)
{
	GError *validate_error = NULL;
	ValidateInfo info = { &valid_secrets[0], &validate_error, FALSE };

	nm_setting_vpn_foreach_secret (s_vpn, validate_one_property, &info);
	if (validate_error) {
		g_propagate_error (error, validate_error);
		return FALSE;
	}
	return TRUE;
}

static void
nm_openvpn_disconnect_management_socket (NMOpenvpnPlugin *plugin)
{
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);
	NMOpenvpnPluginIOData *io_data = priv->io_data;

	/* This should not throw a warning since this can happen in
	   non-password modes */
	if (!io_data)
		return;

	if (io_data->socket_channel_eventid)
		g_source_remove (io_data->socket_channel_eventid);
	if (io_data->socket_channel) {
		g_io_channel_shutdown (io_data->socket_channel, FALSE, NULL);
		g_io_channel_unref (io_data->socket_channel);
	}

	g_free (io_data->username);
	g_free (io_data->proxy_username);
	g_free (io_data->pending_auth);

	if (io_data->password)
		memset (io_data->password, 0, strlen (io_data->password));
	g_free (io_data->password);

	if (io_data->priv_key_pass)
		memset (io_data->priv_key_pass, 0, strlen (io_data->priv_key_pass));
	g_free (io_data->priv_key_pass);

	if (io_data->proxy_password)
		memset (io_data->proxy_password, 0, strlen (io_data->proxy_password));
	g_free (io_data->proxy_password);
	g_free (io_data->challenge_state_id);
	g_free (io_data->challenge_text);

	g_free (priv->io_data);
	priv->io_data = NULL;
}

static char *
ovpn_quote_string (const char *unquoted)
{
	char *quoted = NULL, *q;
	char *u = (char *) unquoted;

	g_return_val_if_fail (unquoted != NULL, NULL);

	/* FIXME: use unpaged memory */
	quoted = q = g_malloc0 (strlen (unquoted) * 2);
	while (*u) {
		/* Escape certain characters */
		if (*u == ' ' || *u == '\\' || *u == '"')
			*q++ = '\\';
		*q++ = *u++;
	}

	return quoted;
}

static char *
get_detail (const char *input, const char *prefix)
{
	const char *end;

	nm_assert (prefix);

	if (!g_str_has_prefix (input, prefix))
		return NULL;

	/* Grab characters until the next ' */
	input += strlen (prefix);
	end = strchr (input, '\'');
	if (end)
		return g_strndup (input, end - input);
	return NULL;
}

/* Parse challenge response protocol message of the form
 * CRV1:flags:state_id:username:text
 */
static gboolean
parse_challenge (const char *failure_reason, char **challenge_state_id, char **challenge_text)
{
	const char *colon[4];

	if (   !failure_reason
	    || !g_str_has_prefix (failure_reason, "CRV1:"))
		return FALSE;

	colon[0] = strchr (failure_reason, ':');
	if (!colon[0])
		return FALSE;

	colon[1] = strchr (colon[0] + 1, ':');
	if (!colon[1])
		return FALSE;

	colon[2] = strchr (colon[1] + 1, ':');
	if (!colon[2])
		return FALSE;

	colon[3] = strchr (colon[2] + 1, ':');
	if (!colon[3])
		return FALSE;

	*challenge_state_id = g_strndup (colon[1] + 1, colon[2] - colon[1] - 1);
	*challenge_text = g_strdup (colon[3] + 1);
	return TRUE;
}

static void
write_user_pass (GIOChannel *channel,
                 const char *authtype,
                 const char *user,
                 const char *pass)
{
	char *quser, *qpass, *buf;

	/* Quote strings passed back to openvpn */
	quser = ovpn_quote_string (user);
	qpass = ovpn_quote_string (pass);
	buf = g_strdup_printf ("username \"%s\" \"%s\"\n"
	                       "password \"%s\" \"%s\"\n",
	                       authtype, quser,
	                       authtype, qpass);
	memset (qpass, 0, strlen (qpass));
	g_free (qpass);
	g_free (quser);

	/* Will always write everything in blocking channels (on success) */
	g_io_channel_write_chars (channel, buf, strlen (buf), NULL, NULL);
	g_io_channel_flush (channel, NULL);

	memset (buf, 0, strlen (buf));
	g_free (buf);
}

static gboolean
handle_auth (NMOpenvpnPluginIOData *io_data,
             const char *requested_auth,
             const char **out_message,
             char ***out_hints)
{
	gboolean handled = FALSE;
	guint i = 0;
	char **hints = NULL;

	g_return_val_if_fail (requested_auth != NULL, FALSE);
	g_return_val_if_fail (out_message != NULL, FALSE);
	g_return_val_if_fail (out_hints != NULL, FALSE);

	if (strcmp (requested_auth, "Auth") == 0) {
		const char *username = io_data->username;

		/* Fall back to the default username if it wasn't overridden by the user */
		if (!username)
			username = io_data->default_username;

		if (username != NULL && io_data->password != NULL && io_data->challenge_state_id) {
			gs_free char *response = NULL;

			response = g_strdup_printf ("CRV1::%s::%s",
			                            io_data->challenge_state_id,
			                            io_data->password);
			write_user_pass (io_data->socket_channel,
			                 requested_auth,
			                 username,
			                 response);
			nm_clear_g_free (&io_data->challenge_state_id);
			nm_clear_g_free (&io_data->challenge_text);
		} else if (username != NULL && io_data->password != NULL) {
			write_user_pass (io_data->socket_channel,
			                 requested_auth,
			                 username,
			                 io_data->password);
		} else {
			hints = g_new0 (char *, 3);
			if (!username) {
				hints[i++] = NM_OPENVPN_KEY_USERNAME;
				*out_message = _("A username is required.");
			}
			if (!io_data->password) {
				hints[i++] = NM_OPENVPN_KEY_PASSWORD;
				*out_message = _("A password is required.");
			}
			if (!username && !io_data->password)
				*out_message = _("A username and password are required.");
			if (io_data->challenge_text)
				*out_message = io_data->challenge_text;
		}
		handled = TRUE;
	} else if (!strcmp (requested_auth, "Private Key")) {
		if (io_data->priv_key_pass) {
			char *qpass, *buf;

			/* Quote strings passed back to openvpn */
			qpass = ovpn_quote_string (io_data->priv_key_pass);
			buf = g_strdup_printf ("password \"%s\" \"%s\"\n", requested_auth, qpass);
			memset (qpass, 0, strlen (qpass));
			g_free (qpass);

			/* Will always write everything in blocking channels (on success) */
			g_io_channel_write_chars (io_data->socket_channel, buf, strlen (buf), NULL, NULL);
			g_io_channel_flush (io_data->socket_channel, NULL);
			g_free (buf);
		} else {
			hints = g_new0 (char *, 2);
			hints[i++] = NM_OPENVPN_KEY_CERTPASS;
			*out_message = _("A private key password is required.");
		}
		handled = TRUE;
	} else if (strcmp (requested_auth, "HTTP Proxy") == 0) {
		if (io_data->proxy_username != NULL && io_data->proxy_password != NULL) {
			write_user_pass (io_data->socket_channel,
			                 requested_auth,
			                 io_data->proxy_username,
			                 io_data->proxy_password);
		} else {
			hints = g_new0 (char *, 3);
			if (!io_data->proxy_username) {
				hints[i++] = NM_OPENVPN_KEY_HTTP_PROXY_USERNAME;
				*out_message = _("An HTTP Proxy username is required.");
			}
			if (!io_data->proxy_password) {
				hints[i++] = NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD;
				*out_message = _("An HTTP Proxy password is required.");
			}
			if (!io_data->proxy_username && !io_data->proxy_password)
				*out_message = _("An HTTP Proxy username and password are required.");
		}
		handled = TRUE;
	}

	*out_hints = hints;
	return handled;
}

static gboolean
handle_management_socket (NMOpenvpnPlugin *plugin,
                          GIOChannel *source,
                          GIOCondition condition,
                          NMVpnPluginFailure *out_failure)
{
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);
	gboolean again = TRUE;
	char *str = NULL, *auth = NULL;
	const char *message = NULL;
	char **hints = NULL;

	g_assert (out_failure);

	if (!(condition & G_IO_IN))
		return TRUE;

	if (g_io_channel_read_line (source, &str, NULL, NULL, NULL) != G_IO_STATUS_NORMAL)
		return TRUE;

	if (!str[0]) {
		g_free (str);
		return TRUE;
	}

	_LOGD ("VPN request '%s'", str);

	auth = get_detail (str, ">PASSWORD:Need '");
	if (auth) {
		if (priv->io_data->pending_auth)
			g_free (priv->io_data->pending_auth);
		priv->io_data->pending_auth = auth;

		if (handle_auth (priv->io_data, auth, &message, &hints)) {
			/* Request new secrets if we need any */
			if (message) {
				if (priv->interactive) {
					gs_free char *joined = NULL;

					_LOGD ("Requesting new secrets: '%s', %s%s%s", message,
					        NM_PRINT_FMT_QUOTED (hints, "(", (joined = g_strjoinv (",", (char **) hints)), ")", "no hints"));

					nm_vpn_service_plugin_secrets_required ((NMVpnServicePlugin *) plugin, message, (const char **) hints);
				} else {
					/* Interactive not allowed, can't ask for more secrets */
					_LOGW ("More secrets required but cannot ask interactively");
					*out_failure = NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED;
					again = FALSE;
				}
			}
			if (hints)
				g_free (hints);  /* elements are 'const' */
		} else {
			_LOGW ("Unhandled management socket request '%s'", auth);
			*out_failure = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;
			again = FALSE;
		}
		goto out;
	}

	auth = get_detail (str, ">PASSWORD:Verification Failed: '");
	if (auth) {
		gboolean fail = TRUE;

		if (!strcmp (auth, "Auth")) {
			gs_free char *failure_reason = NULL;

			failure_reason = get_detail (auth, ">PASSWORD:Verification Failed: 'Auth' ['");
			if (parse_challenge (failure_reason, &priv->io_data->challenge_state_id, &priv->io_data->challenge_text)) {
				_LOGD ("Received challenge '%s' for state '%s'",
				       priv->io_data->challenge_state_id,
				       priv->io_data->challenge_text);
			} else
				_LOGW ("Password verification failed");

			if (priv->interactive) {
				/* Clear existing password in interactive mode, openvpn
				 * will request a new one after restarting.
				 */
				if (priv->io_data->password)
					memset (priv->io_data->password, 0, strlen (priv->io_data->password));
				g_clear_pointer (&priv->io_data->password, g_free);
				fail = FALSE;
			}
		} else if (!strcmp (auth, "Private Key"))
			_LOGW ("Private key verification failed");
		else
			_LOGW ("Unknown verification failed: %s", auth);

		if (fail) {
			*out_failure = NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED;
			again = FALSE;
		}

		g_free (auth);
	}

out:
	g_free (str);
	return again;
}

static gboolean
nm_openvpn_socket_data_cb (GIOChannel *source, GIOCondition condition, gpointer user_data)
{
	NMOpenvpnPlugin *plugin = NM_OPENVPN_PLUGIN (user_data);
	NMVpnPluginFailure failure = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;

	if (!handle_management_socket (plugin, source, condition, &failure)) {
		nm_vpn_service_plugin_failure ((NMVpnServicePlugin *) plugin, failure);
		return FALSE;
	}

	return TRUE;
}

static gboolean
nm_openvpn_connect_timer_cb (gpointer data)
{
	NMOpenvpnPlugin *plugin = NM_OPENVPN_PLUGIN (data);
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);
	NMOpenvpnPluginIOData *io_data = priv->io_data;
	struct sockaddr_un remote = { 0 };
	int fd;

	priv->connect_count++;

	/* open socket and start listener */
	fd = socket (AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		_LOGW ("Could not create management socket");
		nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		goto out;
	}

	remote.sun_family = AF_UNIX;
	g_strlcpy (remote.sun_path, priv->mgt_path, sizeof (remote.sun_path));
	if (connect (fd, (struct sockaddr *) &remote, sizeof (remote)) != 0) {
		close (fd);
		if (priv->connect_count <= 30)
			return G_SOURCE_CONTINUE;

		priv->connect_timer = 0;

		_LOGW ("Could not open management socket");
		nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
	} else {
		io_data->socket_channel = g_io_channel_unix_new (fd);
		g_io_channel_set_encoding (io_data->socket_channel, NULL, NULL);
		io_data->socket_channel_eventid = g_io_add_watch (io_data->socket_channel,
		                                                  G_IO_IN,
		                                                  nm_openvpn_socket_data_cb,
		                                                  plugin);
	}

out:
	priv->connect_timer = 0;
	return G_SOURCE_REMOVE;
}

static void
nm_openvpn_schedule_connect_timer (NMOpenvpnPlugin *plugin)
{
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);

	if (priv->connect_timer == 0)
		priv->connect_timer = g_timeout_add (200, nm_openvpn_connect_timer_cb, plugin);
}

static void
openvpn_child_terminated (NMOpenvpnPlugin *plugin, GPid pid, gint status)
{
	NMOpenvpnPluginPrivate *priv;
	NMVpnPluginFailure failure = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;
	gboolean good_exit = FALSE;

	g_return_if_fail (NM_IS_OPENVPN_PLUGIN (plugin));

	priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);
	/* Reap child if needed. */
	if (priv->pid != pid) {
		/* the dead child is not the currently active process. Nothing to do, we just
		 * reaped the PID. */
		return;
	}

	priv->pid = 0;

	/* OpenVPN doesn't supply useful exit codes :( */
	if (WIFEXITED (status) && WEXITSTATUS (status) == 0)
		good_exit = TRUE;

	/* Try to get the last bits of data from openvpn */
	if (priv->io_data && priv->io_data->socket_channel) {
		GIOChannel *channel = priv->io_data->socket_channel;
		GIOCondition condition;

		while ((condition = g_io_channel_get_buffer_condition (channel)) & G_IO_IN) {
			if (!handle_management_socket (plugin, channel, condition, &failure)) {
				good_exit = FALSE;
				break;
			}
		}
	}

	if (good_exit)
		nm_vpn_service_plugin_disconnect ((NMVpnServicePlugin *) plugin, NULL);
	else
		nm_vpn_service_plugin_failure ((NMVpnServicePlugin *) plugin, failure);
}

static gboolean
validate_auth (const char *auth)
{
	if (auth) {
		if (   !strcmp (auth, NM_OPENVPN_AUTH_NONE)
		    || !strcmp (auth, NM_OPENVPN_AUTH_RSA_MD4)
		    || !strcmp (auth, NM_OPENVPN_AUTH_MD5)
		    || !strcmp (auth, NM_OPENVPN_AUTH_SHA1)
		    || !strcmp (auth, NM_OPENVPN_AUTH_SHA224)
		    || !strcmp (auth, NM_OPENVPN_AUTH_SHA256)
		    || !strcmp (auth, NM_OPENVPN_AUTH_SHA384)
		    || !strcmp (auth, NM_OPENVPN_AUTH_SHA512)
		    || !strcmp (auth, NM_OPENVPN_AUTH_RIPEMD160))
			return TRUE;
	}
	return FALSE;
}

static const char *
validate_connection_type (const char *ctype)
{
	if (ctype) {
		if (   !strcmp (ctype, NM_OPENVPN_CONTYPE_TLS)
		    || !strcmp (ctype, NM_OPENVPN_CONTYPE_STATIC_KEY)
		    || !strcmp (ctype, NM_OPENVPN_CONTYPE_PASSWORD)
		    || !strcmp (ctype, NM_OPENVPN_CONTYPE_PASSWORD_TLS))
			return ctype;
	}
	return NULL;
}

static gboolean
connection_type_is_tls_mode (const char *connection_type)
{
	return strcmp (connection_type, NM_OPENVPN_CONTYPE_TLS) == 0
	    || strcmp (connection_type, NM_OPENVPN_CONTYPE_PASSWORD) == 0
	    || strcmp (connection_type, NM_OPENVPN_CONTYPE_PASSWORD_TLS) == 0;
}

static void
add_openvpn_arg (GPtrArray *args, const char *arg)
{
	g_return_if_fail (args != NULL);
	g_return_if_fail (arg != NULL);

	g_ptr_array_add (args, g_strdup (arg));
}

static const char *
add_openvpn_arg_utf8safe (GPtrArray *args, const char *arg)
{
	char *arg_unescaped;

	g_return_val_if_fail (args, NULL);
	g_return_val_if_fail (arg, NULL);

	arg_unescaped = nm_utils_str_utf8safe_unescape_cp (arg);
	g_ptr_array_add (args, arg_unescaped);
	return arg_unescaped;
}

static gboolean
add_openvpn_arg_int (GPtrArray *args, const char *arg)
{
	long int tmp_int;

	g_return_val_if_fail (args != NULL, FALSE);
	g_return_val_if_fail (arg != NULL, FALSE);

	/* Convert -> int and back to string for security's sake since
	 * strtol() ignores some leading and trailing characters.
	 */
	errno = 0;
	tmp_int = strtol (arg, NULL, 10);
	if (errno != 0)
		return FALSE;
	g_ptr_array_add (args, (gpointer) g_strdup_printf ("%d", (guint32) tmp_int));
	return TRUE;
}

static void
add_cert_args (GPtrArray *args, NMSettingVpn *s_vpn)
{
	const char *ca, *cert, *key;
	gs_free char *ca_free = NULL, *cert_free = NULL, *key_free = NULL;

	g_return_if_fail (args != NULL);
	g_return_if_fail (s_vpn != NULL);

	ca   = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CA);
	cert = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CERT);
	key  = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_KEY);

	ca   = nm_utils_str_utf8safe_unescape (ca,   &ca_free);
	cert = nm_utils_str_utf8safe_unescape (cert, &cert_free);
	key  = nm_utils_str_utf8safe_unescape (key,  &key_free);

	if (   ca && strlen (ca)
	    && cert && strlen (cert)
	    && key && strlen (key)
	    && !strcmp (ca, cert)
	    && !strcmp (ca, key)) {
		add_openvpn_arg (args, "--pkcs12");
		add_openvpn_arg (args, ca);
	} else {
		if (ca && strlen (ca)) {
			add_openvpn_arg (args, "--ca");
			add_openvpn_arg (args, ca);
		}

		if (cert && strlen (cert)) {
			add_openvpn_arg (args, "--cert");
			add_openvpn_arg (args, cert);
		}

		if (key && strlen (key)) {
			add_openvpn_arg (args, "--key");
			add_openvpn_arg (args, key);
		}
	}
}

static void
update_io_data_from_vpn_setting (NMOpenvpnPluginIOData *io_data,
                                 NMSettingVpn *s_vpn,
                                 const char *default_username)
{
	const char *tmp;

	if (default_username) {
		g_free (io_data->default_username);
		io_data->default_username = g_strdup (default_username);
	}

	g_free (io_data->username);
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_USERNAME);
	io_data->username = tmp ? g_strdup (tmp) : NULL;

	if (io_data->password) {
		memset (io_data->password, 0, strlen (io_data->password));
		g_free (io_data->password);
	}
	tmp = nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD);
	io_data->password = tmp ? g_strdup (tmp) : NULL;

	if (io_data->priv_key_pass) {
		memset (io_data->priv_key_pass, 0, strlen (io_data->priv_key_pass));
		g_free (io_data->priv_key_pass);
	}
	tmp = nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS);
	io_data->priv_key_pass = tmp ? g_strdup (tmp) : NULL;

	g_free (io_data->proxy_username);
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_USERNAME);
	io_data->proxy_username = tmp ? g_strdup (tmp) : NULL;

	if (io_data->proxy_password) {
		memset (io_data->proxy_password, 0, strlen (io_data->proxy_password));
		g_free (io_data->proxy_password);
	}
	tmp = nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD);
	io_data->proxy_password = tmp ? g_strdup (tmp) : NULL;
}

static char *
mgt_path_create (NMConnection *connection, GError **error)
{
	int errsv;

	/* Setup runtime directory */
	if (g_mkdir_with_parents (RUNDIR, 0755) != 0) {
		errsv = errno;
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "Cannot create run-dir %s (%s)",
		             RUNDIR, g_strerror (errsv));
		return NULL;
	}

	return g_strdup_printf (RUNDIR"/nm-openvpn-%s",
	                        nm_connection_get_uuid (connection));
}

#define MAX_GROUPS 128
static gboolean
is_dir_writable (const char *dir, const char *user)
{
	struct stat sb;
	struct passwd *pw;

	if (stat (dir, &sb) == -1)
		return FALSE;
	pw = getpwnam (user);
	if (!pw)
		return FALSE;

	if (pw->pw_uid == 0)
		return TRUE;

	if (sb.st_mode & S_IWOTH)
		return TRUE;
	else if (sb.st_mode & S_IWGRP) {
		/* Group has write access. Is user in that group? */
		int i, ngroups = MAX_GROUPS;
		gid_t groups[MAX_GROUPS];

		getgrouplist (user, pw->pw_gid, groups, &ngroups);
		for (i = 0; i < ngroups && i < MAX_GROUPS; i++) {
			if (groups[i] == sb.st_gid)
				return TRUE;
		}
	} else if (sb.st_mode & S_IWUSR) {
		/* The owner has write access. Does the user own the file? */
		if (pw->pw_uid == sb.st_uid)
			return TRUE;
	}
	return FALSE;
}

/* Check existence of 'tmp' directory inside @chdir
 * and write access in @chdir and @chdir/tmp for @user.
 */
static gboolean
check_chroot_dir_usability (const char *chdir, const char *user)
{
	char *tmp_dir;
	gboolean b1, b2;

	tmp_dir = g_strdup_printf ("%s/tmp", chdir);
	if (!g_file_test (tmp_dir, G_FILE_TEST_IS_DIR)) {
		g_free (tmp_dir);
		return FALSE;
	}

	b1 = is_dir_writable (chdir, user);
	b2 = is_dir_writable (tmp_dir, user);
	g_free (tmp_dir);
	return b1 && b2;
}

static gboolean
nm_openvpn_start_openvpn_binary (NMOpenvpnPlugin *plugin,
                                 NMConnection *connection,
                                 GError **error)
{
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);
	const char *openvpn_binary, *auth, *tmp, *tmp2, *tmp3, *tmp4;
	gs_unref_ptrarray GPtrArray *args = NULL;
	GPid pid;
	gboolean dev_type_is_tap;
	char *stmp;
	const char *defport, *proto_tcp;
	const char *tls_remote = NULL;
	const char *nm_openvpn_user, *nm_openvpn_group, *nm_openvpn_chroot;
	gs_free char *bus_name = NULL;
	NMSettingVpn *s_vpn;
	const char *connection_type;
	gint64 v_int64;
	char sbuf_64[65];
	OpenvpnBinaryVersion openvpn_binary_version = OPENVPN_BINARY_VERSION_INVALID;

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		                     _("Could not process the request because the VPN connection settings were invalid."));
		return FALSE;
	}

	connection_type = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE);
	if (!validate_connection_type (connection_type)) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		                     _("Invalid connection type."));
		return FALSE;
	}

	/* Validate the properties */
	if (!nm_openvpn_properties_validate (s_vpn, error))
		return FALSE;

	/* Validate secrets */
	if (!nm_openvpn_secrets_validate (s_vpn, error))
		return FALSE;

	/* Find openvpn */
	openvpn_binary = openvpn_binary_find_exepath ();
	if (!openvpn_binary) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		                     _("Could not find the openvpn binary."));
		return FALSE;
	}

	auth = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_AUTH);
	if (auth) {
		if (!validate_auth(auth)) {
			g_set_error_literal (error,
			                     NM_VPN_PLUGIN_ERROR,
			                     NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			                     _("Invalid HMAC auth."));
			return FALSE;
		}
	}

	args = g_ptr_array_new_with_free_func (g_free);

	add_openvpn_arg (args, openvpn_binary);

	defport = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PORT);
	if (defport && !defport[0])
		defport = NULL;

	proto_tcp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP);
	if (proto_tcp && !proto_tcp[0])
		proto_tcp = NULL;

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE);
	if (tmp && *tmp) {
		gs_free char *tmp_clone = NULL;
		char *tmp_remaining;
		const char *tok;

		tmp_remaining = tmp_clone = g_strdup (tmp);
		while ((tok = strsep (&tmp_remaining, " \t,")) != NULL) {
			gs_free char *str_free = NULL;
			const char *host, *port, *proto;
			gssize eidx;

			eidx = nmovpn_remote_parse (tok,
			                            &str_free,
			                            &host,
			                            &port,
			                            &proto,
			                            NULL);
			if (eidx >= 0)
				continue;

			add_openvpn_arg (args, "--remote");
			add_openvpn_arg (args, host);
			if (port) {
				if (!add_openvpn_arg_int (args, port)) {
					g_set_error (error,
					             NM_VPN_PLUGIN_ERROR,
					             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
					             _("Invalid port number “%s”."), port);
					return FALSE;
				}
			} else if (defport) {
				if (!add_openvpn_arg_int (args, defport)) {
					g_set_error (error,
					             NM_VPN_PLUGIN_ERROR,
					             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
					             _("Invalid port number “%s”."),
					             defport);
					return FALSE;
				}
			} else
				add_openvpn_arg (args, "1194"); /* default IANA port */

			if (proto) {
				if (nm_streq (proto, "tcp"))
					add_openvpn_arg (args, "tcp-client");
				else if (nm_streq (proto, "tcp4"))
					add_openvpn_arg (args, "tcp4-client");
				else if (nm_streq (proto, "tcp6"))
					add_openvpn_arg (args, "tcp6-client");
				else if (NM_IN_STRSET (proto, NMOVPN_PROTCOL_TYPES))
					add_openvpn_arg (args, proto);
				else {
					g_set_error (error,
					             NM_VPN_PLUGIN_ERROR,
					             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
					             _("Invalid proto “%s”."), proto);
					return FALSE;
				}
			} else if (proto_tcp && !strcmp (proto_tcp, "yes"))
				add_openvpn_arg (args, "tcp-client");
			else
				add_openvpn_arg (args, "udp");
		}
	}

	/* Remote random */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_RANDOM);
	if (tmp && !strcmp (tmp, "yes"))
		add_openvpn_arg (args, "--remote-random");

	/* tun-ipv6 */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TUN_IPV6);
	if (tmp && !strcmp (tmp, "yes"))
		add_openvpn_arg (args, "--tun-ipv6");

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PROXY_TYPE);
	tmp2 = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PROXY_SERVER);
	tmp3 = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PROXY_PORT);
	tmp4 = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PROXY_RETRY);
	if (tmp && strlen (tmp) && tmp2 && strlen (tmp2)) {
		if (!strcmp (tmp, "http")) {
			add_openvpn_arg (args, "--http-proxy");
			add_openvpn_arg (args, tmp2);
			add_openvpn_arg (args, tmp3 ? tmp3 : "8080");
			add_openvpn_arg (args, "auto");  /* Automatic proxy auth method detection */
			if (tmp4)
				add_openvpn_arg (args, "--http-proxy-retry");
		} else if (!strcmp (tmp, "socks")) {
			add_openvpn_arg (args, "--socks-proxy");
			add_openvpn_arg (args, tmp2);
			add_openvpn_arg (args, tmp3 ? tmp3 : "1080");
			if (tmp4)
				add_openvpn_arg (args, "--socks-proxy-retry");
		} else {
			g_set_error (error,
				         NM_VPN_PLUGIN_ERROR,
				         NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
				         _("Invalid proxy type “%s”."),
				         tmp);
			return FALSE;
		}
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO);

	/* openvpn understands 4 different modes for --comp-lzo, which have
	 * different meaning:
	 *  1) no --comp-lzo option
	 *  2) --comp-lzo yes
	 *  3) --comp-lzo [adaptive]
	 *  4) --comp-lzo no
	 *
	 * In the past, nm-openvpn only supported 1) and 2) by having no
	 * comp-lzo connection setting or "comp-lzo=yes", respectively.
	 *
	 * However, old plasma-nm would set "comp-lzo=no" in the connection
	 * to mean 1). Thus, "comp-lzo=no" is spoiled to mean 4) in order
	 * to preserve backward compatibily.
	 * We use instead a special value "no-by-default" to express "no".
	 *
	 * See bgo#769177
	 */
	if (NM_IN_STRSET (tmp, "no")) {
		/* means no --comp-lzo option. */
		tmp = NULL;
	} else if (NM_IN_STRSET (tmp, "no-by-default"))
		tmp = "no";

	if (NM_IN_STRSET (tmp, "yes", "no", "adaptive")) {
		add_openvpn_arg (args, "--comp-lzo");
		add_openvpn_arg (args, tmp);
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_FLOAT);
	if (tmp && !strcmp (tmp, "yes"))
		add_openvpn_arg (args, "--float");

	/* ping, ping-exit, ping-restart */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PING);
	if (tmp) {
		add_openvpn_arg (args, "--ping");
		if (!add_openvpn_arg_int (args, tmp)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid ping duration “%s”."),
			             tmp);
			return FALSE;
		}
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PING_EXIT);
	if (tmp) {
		add_openvpn_arg (args, "--ping-exit");
		if (!add_openvpn_arg_int (args, tmp)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid ping-exit duration “%s”."),
			             tmp);
			return FALSE;
		}
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PING_RESTART);
	if (tmp) {
		add_openvpn_arg (args, "--ping-restart");
		if (!add_openvpn_arg_int (args, tmp)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid ping-restart duration “%s”."),
			             tmp);
			return FALSE;
		}
	}

	add_openvpn_arg (args, "--nobind");

	/* max routes allowed from openvpn server */
	tmp = nm_setting_vpn_get_data_item(s_vpn, NM_OPENVPN_KEY_MAX_ROUTES);
	if (tmp) {
		/* max-routes option is deprecated in 2.4 release
		 * https://github.com/OpenVPN/openvpn/commit/d0085293e709c8a722356cfa68ad74c962aef9a2
		 */
		add_openvpn_arg (args, "--max-routes");
		if (!add_openvpn_arg_int (args, tmp)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid max-routes argument “%s”."),
			             tmp);
			return FALSE;
		}
	}

	/* Device and device type, defaults to tun */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_DEV);
	tmp2 = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_DEV_TYPE);
	tmp3 = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TAP_DEV);
	add_openvpn_arg (args, "--dev");
	if (tmp) {
		const char *tmp_unescaped;

		tmp_unescaped = add_openvpn_arg_utf8safe (args, tmp);
		dev_type_is_tap = g_str_has_prefix (tmp_unescaped, "tap");
	} else if (tmp2) {
		add_openvpn_arg (args, tmp2);
		dev_type_is_tap = FALSE; /* will be reset below (avoid maybe-uninitialized warning) */
	} else if (tmp3 && !strcmp (tmp3, "yes")) {
		add_openvpn_arg (args, "tap");
		dev_type_is_tap = TRUE;
	} else {
		add_openvpn_arg (args, "tun");
		dev_type_is_tap = FALSE;
	}

	/* Add '--dev-type' if the type was explicitly set */
	if (tmp2) {
		add_openvpn_arg (args, "--dev-type");
		add_openvpn_arg (args, tmp2);
		dev_type_is_tap = (strcmp (tmp2, "tap") == 0);
	}

	/* Cipher */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CIPHER);
	if (tmp && tmp[0]) {
		add_openvpn_arg (args, "--cipher");
		add_openvpn_arg (args, tmp);
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TLS_CIPHER);
	if (tmp && tmp[0]) {
		add_openvpn_arg (args, "--tls-cipher");
		add_openvpn_arg (args, tmp);
	}

	/* Keysize */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_KEYSIZE);
	if (tmp && tmp[0]) {
		add_openvpn_arg (args, "--keysize");
		if (!add_openvpn_arg_int (args, tmp)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid keysize “%s”."),
			             tmp);
			return FALSE;
		}
	}

	/* Auth */
	if (auth) {
		add_openvpn_arg (args, "--auth");
		add_openvpn_arg (args, auth);
	}
	add_openvpn_arg (args, "--auth-nocache");

	/* tls-auth */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TA);
	if (tmp && tmp[0]) {
		add_openvpn_arg (args, "--tls-auth");
		add_openvpn_arg_utf8safe (args, tmp);

		tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TA_DIR);
		if (tmp && tmp[0])
			add_openvpn_arg (args, tmp);
	}

	/* tls-crypt */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TLS_CRYPT);
	if (tmp && tmp[0]) {
		add_openvpn_arg (args, "--tls-crypt");
		add_openvpn_arg_utf8safe (args, tmp);
	}

	
	/* tls-remote */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TLS_REMOTE);
	if (tmp && tmp[0]) {
		if (openvpn_binary_detect_version_cached (openvpn_binary, &openvpn_binary_version) != OPENVPN_BINARY_VERSION_2_4_OR_NEWER) {
			_LOGW ("the tls-remote option is deprecated and removed from OpenVPN 2.4. Update your connection to use verify-x509-name");
			add_openvpn_arg (args, "--tls-remote");
			add_openvpn_arg (args, tmp);
		} else {
			_LOGW ("the tls-remote option is deprecated and removed from OpenVPN 2.4. For compatibility, the plugin uses \"verify-x509-name\" \"%s\" \"name\" instead. Update your connection to use verify-x509-name", tmp);
			add_openvpn_arg (args, "--verify-x509-name");
			add_openvpn_arg (args, tmp);
			add_openvpn_arg (args, "name");
		}
		tls_remote = tmp;
	}

	/* verify-x509-name */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_VERIFY_X509_NAME);
	if (tmp && tmp[0]) {
		const char *name;
		gs_free char *type = NULL;

		if (tls_remote) {
			g_set_error (error, NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid configuration with tls-remote and verify-x509-name."));
			return FALSE;
		}

		name = strchr (tmp, ':');
		if (name) {
			type = g_strndup (tmp, name - tmp);
			name++;
		} else
			name = tmp;

		if (!name[0] || !g_utf8_validate(name, -1, NULL)) {
			g_set_error (error, NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid verify-x509-name."));
			return FALSE;
		}

		add_openvpn_arg (args, "--verify-x509-name");
		add_openvpn_arg (args, name);
		add_openvpn_arg (args, type ?: "subject");
	}

	/* remote-cert-tls */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_CERT_TLS);
	if (tmp && tmp[0]) {
		add_openvpn_arg (args, "--remote-cert-tls");
		add_openvpn_arg (args, tmp);
	}

	/* ns-cert-type */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_NS_CERT_TYPE);
	if (tmp && tmp[0]) {
		add_openvpn_arg (args, "--ns-cert-type");
		add_openvpn_arg (args, tmp);
	}

	/* Reneg seconds */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS);
	if (!connection_type_is_tls_mode (connection_type)) {
		/* Ignore --reneg-sec option if we are not in TLS mode (as enabled
		 * by --client below). openvpn will error out otherwise, see bgo#749050. */
	} else if (tmp && tmp[0]) {
		add_openvpn_arg (args, "--reneg-sec");
		if (!add_openvpn_arg_int (args, tmp)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid reneg seconds “%s”."),
			             tmp);
			return FALSE;
		}
	} else {
		/* Either the server and client must agree on the renegotiation
		 * interval, or it should be disabled on one side to prevent
		 * too-frequent renegotiations, which make two-factor auth quite
		 * painful.
		 */
		add_openvpn_arg (args, "--reneg-sec");
		add_openvpn_arg (args, "0");
	}

	if (gl.log_level_ovpn >= 0) {
		add_openvpn_arg (args, "--verb");
		add_openvpn_arg (args, nm_sprintf_buf (sbuf_64, "%d", gl.log_level_ovpn));
	}

	if (gl.log_syslog) {
		add_openvpn_arg (args, "--syslog");
		add_openvpn_arg (args, "nm-openvpn");
	}

	/* TUN MTU size */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TUNNEL_MTU);
	if (tmp && tmp[0]) {
		add_openvpn_arg (args, "--tun-mtu");
		if (!add_openvpn_arg_int (args, tmp)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid TUN MTU size “%s”."),
			             tmp);
			return FALSE;
		}
	}

	/* fragment size */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_FRAGMENT_SIZE);
	if (tmp && tmp[0]) {
		add_openvpn_arg (args, "--fragment");
		if (!add_openvpn_arg_int (args, tmp)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid fragment size “%s”."),
			             tmp);
			return FALSE;
		}
	}

	/* mssfix */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_MSSFIX);
	if (tmp) {
		if (nm_streq (tmp, "yes"))
			add_openvpn_arg (args, "--mssfix");
		else if ((v_int64 = _nm_utils_ascii_str_to_int64 (tmp, 10, 1, G_MAXINT32, 0))) {
			add_openvpn_arg (args, "--mssfix");
			add_openvpn_arg (args, nm_sprintf_buf (sbuf_64, "%d", (int) v_int64));
		}
	}

	/* mtu-disc */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_MTU_DISC);
	if (NM_IN_STRSET (tmp, "no", "maybe", "yes")) {
		add_openvpn_arg (args, "--mtu-disc");
		add_openvpn_arg (args, tmp);
	}

	/* ifconfig */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP);
	tmp2 = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP);
	if (tmp && tmp2) {
		add_openvpn_arg (args, "--ifconfig");
		add_openvpn_arg (args, tmp);
		add_openvpn_arg (args, tmp2);
	}

	/* Punch script security in the face; this option was added to OpenVPN 2.1-rc9
	 * and defaults to disallowing any scripts, a behavior change from previous
	 * versions.
	 */
	add_openvpn_arg (args, "--script-security");
	add_openvpn_arg (args, "2");

	/* Up script, called when connection has been established or has been restarted */
	add_openvpn_arg (args, "--up");
	g_object_get (plugin, NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME, &bus_name, NULL);
	stmp = g_strdup_printf ("%s --debug %d %ld --bus-name %s %s --",
	                        NM_OPENVPN_HELPER_PATH,
	                        gl.log_level, (long) getpid(),
	                        bus_name,
	                        dev_type_is_tap ? "--tap" : "--tun");
	add_openvpn_arg (args, stmp);
	g_free (stmp);
	add_openvpn_arg (args, "--up-restart");

	/* Keep key and tun if restart is needed */
	add_openvpn_arg (args, "--persist-key");
	add_openvpn_arg (args, "--persist-tun");

	/* Management socket for localhost access to supply username and password */
	g_clear_pointer (&priv->mgt_path, g_free);
	priv->mgt_path = mgt_path_create (connection, error);
	if (!priv->mgt_path)
		return FALSE;
	add_openvpn_arg (args, "--management");
	add_openvpn_arg (args, priv->mgt_path);
	add_openvpn_arg (args, "unix");
	add_openvpn_arg (args, "--management-client-user");
	add_openvpn_arg (args, "root");
	add_openvpn_arg (args, "--management-client-group");
	add_openvpn_arg (args, "root");

	/* Query on the management socket for user/pass */
	add_openvpn_arg (args, "--management-query-passwords");
	add_openvpn_arg (args, "--auth-retry");
	add_openvpn_arg (args, "interact");

	/* do not let openvpn setup routes or addresses, NM will handle it */
	add_openvpn_arg (args, "--route-noexec");
	add_openvpn_arg (args, "--ifconfig-noexec");

	/* Now append configuration options which are dependent on the configuration type */
	if (!strcmp (connection_type, NM_OPENVPN_CONTYPE_TLS)) {
		add_openvpn_arg (args, "--client");
		add_cert_args (args, s_vpn);
	} else if (!strcmp (connection_type, NM_OPENVPN_CONTYPE_STATIC_KEY)) {
		tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY);
		if (tmp && tmp[0]) {
			add_openvpn_arg (args, "--secret");
			add_openvpn_arg_utf8safe (args, tmp);

			tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION);
			if (tmp && tmp[0])
				add_openvpn_arg (args, tmp);
		}
	} else if (!strcmp (connection_type, NM_OPENVPN_CONTYPE_PASSWORD)) {
		/* Client mode */
		add_openvpn_arg (args, "--client");
		/* Use user/path authentication */
		add_openvpn_arg (args, "--auth-user-pass");

		tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CA);
		if (tmp && tmp[0]) {
			add_openvpn_arg (args, "--ca");
			add_openvpn_arg_utf8safe (args, tmp);
		}
	} else if (!strcmp (connection_type, NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
		add_openvpn_arg (args, "--client");
		add_cert_args (args, s_vpn);
		/* Use user/path authentication */
		add_openvpn_arg (args, "--auth-user-pass");
	} else {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             _("Unknown connection type “%s”."),
		             connection_type);
		return FALSE;
	}

	/* Allow openvpn to be run as a specified user:group.
	 *
	 * We do this by default. The only way to disable it is by setting
	 * empty environment variables NM_OPENVPN_USER and NM_OPENVPN_GROUP. */
	nm_openvpn_user = getenv ("NM_OPENVPN_USER") ?: NM_OPENVPN_USER;
	nm_openvpn_group = getenv ("NM_OPENVPN_GROUP") ?: NM_OPENVPN_GROUP;
	if (*nm_openvpn_user) {
		if (getpwnam (nm_openvpn_user)) {
			add_openvpn_arg (args, "--user");
			add_openvpn_arg (args, nm_openvpn_user);
		} else {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("User “%s” not found, check NM_OPENVPN_USER."),
			             nm_openvpn_user);
			return FALSE;
		}
	}
	if (*nm_openvpn_group) {
		if (getgrnam (nm_openvpn_group)) {
			add_openvpn_arg (args, "--group");
			add_openvpn_arg (args, nm_openvpn_group);
		} else {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Group “%s” not found, check NM_OPENVPN_GROUP."),
			             nm_openvpn_group);
			return FALSE;
		}
	}

	/* we try to chroot be default. The only way to disable that is by
	 * setting the an empty environment variable NM_OPENVPN_CHROOT. */
	nm_openvpn_chroot = getenv ("NM_OPENVPN_CHROOT") ?: NM_OPENVPN_CHROOT;
	if (*nm_openvpn_chroot) {
		if (check_chroot_dir_usability (nm_openvpn_chroot, nm_openvpn_user)) {
			add_openvpn_arg (args, "--chroot");
			add_openvpn_arg (args, nm_openvpn_chroot);
		} else
			_LOGW ("Directory '%s' not usable for chroot by '%s', openvpn will not be chrooted.",
			        nm_openvpn_chroot, nm_openvpn_user);
	}

	g_ptr_array_add (args, NULL);

	{
		gs_free char *cmd = NULL;

		_LOGD ("EXEC: '%s'", (cmd = g_strjoinv (" ", (char **) args->pdata)));
	}

	if (!g_spawn_async (NULL, (char **) args->pdata, NULL,
	                    G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, error))
		return FALSE;

	pids_pending_add (pid, plugin);

	g_warn_if_fail (!priv->pid);
	priv->pid = pid;

	/* Listen to the management socket for a few connection types:
	   PASSWORD: Will require username and password
	   X509USERPASS: Will require username and password and maybe certificate password
	   X509: May require certificate password
	*/
	if (   !strcmp (connection_type, NM_OPENVPN_CONTYPE_TLS)
	    || !strcmp (connection_type, NM_OPENVPN_CONTYPE_PASSWORD)
	    || !strcmp (connection_type, NM_OPENVPN_CONTYPE_PASSWORD_TLS)
	    || nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_USERNAME)) {

		priv->io_data = g_malloc0 (sizeof (NMOpenvpnPluginIOData));
		update_io_data_from_vpn_setting (priv->io_data, s_vpn,
		                                 nm_setting_vpn_get_user_name (s_vpn));
		nm_openvpn_schedule_connect_timer (plugin);
	}

	return TRUE;
}

static const char *
check_need_secrets (NMSettingVpn *s_vpn, gboolean *need_secrets)
{
	const char *tmp, *key, *ctype;
	NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;
	gs_free char *key_free = NULL;

	g_return_val_if_fail (s_vpn != NULL, FALSE);
	g_return_val_if_fail (need_secrets != NULL, FALSE);

	*need_secrets = FALSE;

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE);
	ctype = validate_connection_type (tmp);
	if (!ctype)
		return NULL;

	if (!strcmp (ctype, NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
		/* Will require a password and maybe private key password */
		key = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_KEY);
		key = nm_utils_str_utf8safe_unescape (key, &key_free);
		if (is_encrypted (key) && !nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS))
			*need_secrets = TRUE;

		if (!nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD)) {
			*need_secrets = TRUE;
			if (nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_OPENVPN_KEY_PASSWORD, &secret_flags, NULL)) {
				if (secret_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
					*need_secrets = FALSE;
			}
		}
	} else if (!strcmp (ctype, NM_OPENVPN_CONTYPE_PASSWORD)) {
		/* Will require a password */
		if (!nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD)) {
			*need_secrets = TRUE;
			if (nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_OPENVPN_KEY_PASSWORD, &secret_flags, NULL)) {
				if (secret_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
					*need_secrets = FALSE;
			}
		}
	} else if (!strcmp (ctype, NM_OPENVPN_CONTYPE_TLS)) {
		/* May require private key password */
		key = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_KEY);
		key = nm_utils_str_utf8safe_unescape (key, &key_free);
		if (is_encrypted (key) && !nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS))
			*need_secrets = TRUE;
	} else {
		/* Static key doesn't need passwords */
	}

	/* HTTP Proxy might require a password; assume so if there's an HTTP proxy username */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_USERNAME);
	if (tmp && !nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD))
		*need_secrets = TRUE;

	return ctype;
}

static gboolean
real_disconnect (NMVpnServicePlugin *plugin,
                 GError **err)
{
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);

	if (priv->mgt_path) {
		/* openvpn does not cleanup the management socket upon exit,
		 * possibly it could not even because it changed user */
		(void) unlink (priv->mgt_path);
		g_clear_pointer (&priv->mgt_path, g_free);
	}

	if (priv->pid) {
		pids_pending_send_sigterm (priv->pid);
		priv->pid = 0;
	}

	return TRUE;
}

static gboolean
_connect_common (NMVpnServicePlugin   *plugin,
                 NMConnection  *connection,
                 GVariant      *details,
                 GError       **error)
{
	GError *local = NULL;

	if (!real_disconnect (plugin, &local)) {
		_LOGW ("Could not clean up previous daemon run: %s", local->message);
		g_error_free (local);
	}

	return nm_openvpn_start_openvpn_binary (NM_OPENVPN_PLUGIN (plugin),
	                                        connection,
	                                        error);
}

static gboolean
real_connect (NMVpnServicePlugin   *plugin,
              NMConnection  *connection,
              GError       **error)
{
	return _connect_common (plugin, connection, NULL, error);
}

static gboolean
real_connect_interactive (NMVpnServicePlugin   *plugin,
                          NMConnection  *connection,
                          GVariant      *details,
                          GError       **error)
{
	if (!_connect_common (plugin, connection, details, error))
		return FALSE;

	NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin)->interactive = TRUE;
	return TRUE;
}

static gboolean
real_need_secrets (NMVpnServicePlugin *plugin,
                   NMConnection *connection,
                   const char **setting_name,
                   GError **error)
{
	NMSettingVpn *s_vpn;
	const char *connection_type;
	gboolean need_secrets = FALSE;

	g_return_val_if_fail (NM_IS_VPN_SERVICE_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	if (_LOGD_enabled ()) {
		_LOGD ("connection -------------------------------------");
		nm_connection_dump (connection);
	}

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		                     _("Could not process the request because the VPN connection settings were invalid."));
		return FALSE;
	}

	connection_type = check_need_secrets (s_vpn, &need_secrets);
	if (!connection_type) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		                     _("Invalid connection type."));
		return FALSE;
	}

	if (need_secrets)
		*setting_name = NM_SETTING_VPN_SETTING_NAME;

	return need_secrets;
}

static gboolean
real_new_secrets (NMVpnServicePlugin *plugin,
                  NMConnection *connection,
                  GError **error)
{
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);
	NMSettingVpn *s_vpn;
	const char *message = NULL;
	char **hints = NULL;

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		                     _("Could not process the request because the VPN connection settings were invalid."));
		return FALSE;
	}

	_LOGD ("VPN received new secrets; sending to management interface");

	update_io_data_from_vpn_setting (priv->io_data, s_vpn, NULL);

	g_warn_if_fail (priv->io_data->pending_auth);
	if (!handle_auth (priv->io_data, priv->io_data->pending_auth, &message, &hints)) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_FAILED,
		                     _("Unhandled pending authentication."));
		return FALSE;
	}

	/* Request new secrets if we need any */
	if (message) {
		_LOGD ("Requesting new secrets: '%s'", message);
		nm_vpn_service_plugin_secrets_required (plugin, message, (const char **) hints);
	}
	if (hints)
		g_free (hints);  /* elements are 'const' */
	return TRUE;
}

static void
nm_openvpn_plugin_init (NMOpenvpnPlugin *plugin)
{
}

static void
dispose (GObject *object)
{
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (object);

	nm_clear_g_source (&priv->connect_timer);

	if (priv->pid) {
		pids_pending_send_sigterm (priv->pid);
		priv->pid = 0;
	}

	G_OBJECT_CLASS (nm_openvpn_plugin_parent_class)->dispose (object);
}

static void
nm_openvpn_plugin_class_init (NMOpenvpnPluginClass *plugin_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (plugin_class);
	NMVpnServicePluginClass *parent_class = NM_VPN_SERVICE_PLUGIN_CLASS (plugin_class);

	g_type_class_add_private (object_class, sizeof (NMOpenvpnPluginPrivate));

	object_class->dispose = dispose;

	/* virtual methods */
	parent_class->connect      = real_connect;
	parent_class->connect_interactive = real_connect_interactive;
	parent_class->need_secrets = real_need_secrets;
	parent_class->disconnect   = real_disconnect;
	parent_class->new_secrets  = real_new_secrets;
}

static void
plugin_state_changed (NMOpenvpnPlugin *plugin,
                      NMVpnServiceState state,
                      gpointer user_data)
{
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);

	switch (state) {
	case NM_VPN_SERVICE_STATE_UNKNOWN:
	case NM_VPN_SERVICE_STATE_INIT:
	case NM_VPN_SERVICE_STATE_SHUTDOWN:
	case NM_VPN_SERVICE_STATE_STOPPING:
	case NM_VPN_SERVICE_STATE_STOPPED:
		/* Cleanup on failure */
		nm_clear_g_source (&priv->connect_timer);
		nm_openvpn_disconnect_management_socket (plugin);
		break;
	default:
		break;
	}
}

NMOpenvpnPlugin *
nm_openvpn_plugin_new (const char *bus_name)
{
	NMOpenvpnPlugin *plugin;
	GError *error = NULL;

	plugin =  (NMOpenvpnPlugin *) g_initable_new (NM_TYPE_OPENVPN_PLUGIN, NULL, &error,
	                                              NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME, bus_name,
	                                              NM_VPN_SERVICE_PLUGIN_DBUS_WATCH_PEER, !gl.debug,
	                                              NULL);

	if (plugin) {
		g_signal_connect (G_OBJECT (plugin), "state-changed", G_CALLBACK (plugin_state_changed), NULL);
	} else {
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
	NMOpenvpnPlugin *plugin;
	gboolean persist = FALSE;
	GOptionContext *opt_ctx = NULL;
	gchar *bus_name = NM_DBUS_SERVICE_OPENVPN;
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

	if (getenv ("OPENVPN_DEBUG"))
		gl.debug = TRUE;

	/* locale will be set according to environment LC_* variables */
	setlocale (LC_ALL, "");

	bindtextdomain (GETTEXT_PACKAGE, NM_OPENVPN_LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	/* Parse options */
	opt_ctx = g_option_context_new (NULL);
	g_option_context_set_translation_domain (opt_ctx, GETTEXT_PACKAGE);
	g_option_context_set_ignore_unknown_options (opt_ctx, FALSE);
	g_option_context_set_help_enabled (opt_ctx, TRUE);
	g_option_context_add_main_entries (opt_ctx, options, NULL);

	g_option_context_set_summary (opt_ctx,
	                              _("nm-openvpn-service provides integrated "
	                                "OpenVPN capability to NetworkManager."));

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

	_LOGD ("nm-openvpn-service (version " DIST_VERSION ") starting...");

	if (   !g_file_test ("/sys/class/misc/tun", G_FILE_TEST_EXISTS)
	    && (system ("/sbin/modprobe tun") == -1))
		exit (EXIT_FAILURE);

	plugin = nm_openvpn_plugin_new (bus_name);
	if (!plugin)
		exit (EXIT_FAILURE);

	loop = g_main_loop_new (NULL, FALSE);

	if (!persist)
		g_signal_connect (plugin, "quit", G_CALLBACK (quit_mainloop), loop);

	signal (SIGPIPE, SIG_IGN);
	g_unix_signal_add (SIGTERM, signal_handler, loop);
	g_unix_signal_add (SIGINT, signal_handler, loop);

	g_main_loop_run (loop);
	g_object_unref (plugin);

	pids_pending_wait_for_processes (loop);

	g_main_loop_unref (loop);

	exit (EXIT_SUCCESS);
}
