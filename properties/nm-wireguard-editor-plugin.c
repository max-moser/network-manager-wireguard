/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * nm-wireguard-editor-plugin.c : GNOME UI dialogs for configuring wireguard VPN connections
 *
 * Copyright (C) 2005 Tim Niemueller <tim@niemueller.de>
 * Copyright (C) 2008 - 2010 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
 * Based on work by David Zeuthen, <davidz@redhat.com>
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
 **************************************************************************/

#include "nm-default.h"

#include "nm-wireguard-editor-plugin.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef NM_VPN_OLD
#include "nm-wireguard-editor.h"
#else
#include "nm-utils/nm-vpn-plugin-utils.h"
#endif

#include "import-export.h"

#define WIREGUARD_PLUGIN_NAME    "Wireguard"
#define WIREGUARD_PLUGIN_DESC    "Used to set up client-side Wireguard connections."

/*****************************************************************************/

enum {
	PROP_0,
	PROP_NAME,
	PROP_DESC,
	PROP_SERVICE
};

static void wireguard_editor_plugin_interface_init (NMVpnEditorPluginInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (WireguardEditorPlugin, wireguard_editor_plugin, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR_PLUGIN,
                                               wireguard_editor_plugin_interface_init))

/*****************************************************************************/

static NMConnection *
import (NMVpnEditorPlugin *iface, const char *path, GError **error)
{
	NMConnection *connection = NULL;
	char *contents = NULL;
	char *ext;
	gsize contents_len;

	ext = strrchr (path, '.');

	if (!ext || (   !g_str_has_suffix (ext, ".wireguard")
	             && !g_str_has_suffix (ext, ".wg")
	             && !g_str_has_suffix (ext, ".cnf")
	             && !g_str_has_suffix (ext, ".conf"))) {   /* Special extension for testcases */
		g_set_error_literal (error,
		                     NMV_EDITOR_PLUGIN_ERROR,
		                     NMV_EDITOR_PLUGIN_ERROR_FILE_NOT_VPN,
		                     "Unknown Wireguard file extension");
		goto out;
	}

	if (!g_file_get_contents (path, &contents, &contents_len, error))
		return NULL;

	connection = do_import (path, contents, contents_len, error);

out:
	g_free (contents);
	return connection;
}

static gboolean
export (NMVpnEditorPlugin *iface,
        const char *path,
        NMConnection *connection,
        GError **error)
{
	return do_export (path, connection, error);
}

static char *
get_suggested_filename (NMVpnEditorPlugin *iface, NMConnection *connection)
{
	NMSettingConnection *s_con;
	const char *id;

	g_return_val_if_fail (connection != NULL, NULL);

	s_con = nm_connection_get_setting_connection (connection);
	g_return_val_if_fail (s_con != NULL, NULL);

	id = nm_setting_connection_get_id (s_con);
	g_return_val_if_fail (id != NULL, NULL);

	return g_strdup_printf ("%s.conf", id);
}

static guint32
get_capabilities (NMVpnEditorPlugin *iface)
{
	return (NM_VPN_EDITOR_PLUGIN_CAPABILITY_IMPORT |
	        NM_VPN_EDITOR_PLUGIN_CAPABILITY_EXPORT);
	        //NM_VPN_EDITOR_PLUGIN_CAPABILITY_IPV6);
}

#ifndef NM_VPN_OLD
static NMVpnEditor *
_call_editor_factory (gpointer factory,
                      NMVpnEditorPlugin *editor_plugin,
                      NMConnection *connection,
                      gpointer user_data,
                      GError **error)
{
	return ((NMVpnEditorFactory) factory) (editor_plugin,
	                                       connection,
	                                       error);
}
#endif

static NMVpnEditor *
get_editor (NMVpnEditorPlugin *iface, NMConnection *connection, GError **error)
{
	g_return_val_if_fail (WIREGUARD_IS_EDITOR_PLUGIN (iface), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	{
#ifdef NM_VPN_OLD
		return wireguard_editor_new (connection, error);
#else
		return nm_vpn_plugin_utils_load_editor (NM_PLUGIN_DIR"/libnm-vpn-plugin-wireguard-editor.so",
		                                        "nm_vpn_editor_factory_wireguard",
		                                        _call_editor_factory,
		                                        iface,
		                                        connection,
		                                        NULL,
		                                        error);
#endif
	}
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, WIREGUARD_PLUGIN_NAME);
		break;
	case PROP_DESC:
		g_value_set_string (value, WIREGUARD_PLUGIN_DESC);
		break;
	case PROP_SERVICE:
		g_value_set_string (value, NM_VPN_SERVICE_TYPE_WIREGUARD);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
wireguard_editor_plugin_init (WireguardEditorPlugin *plugin)
{
}

static void
wireguard_editor_plugin_interface_init (NMVpnEditorPluginInterface *iface_class)
{
	iface_class->get_editor = get_editor;
	iface_class->get_capabilities = get_capabilities;
	iface_class->import_from_file = import;
	iface_class->export_to_file = export;
	iface_class->get_suggested_filename = get_suggested_filename;
}

static void
wireguard_editor_plugin_class_init (WireguardEditorPluginClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	object_class->get_property = get_property;

	g_object_class_override_property (object_class,
	                                  PROP_NAME,
	                                  NM_VPN_EDITOR_PLUGIN_NAME);

	g_object_class_override_property (object_class,
	                                  PROP_DESC,
	                                  NM_VPN_EDITOR_PLUGIN_DESCRIPTION);

	g_object_class_override_property (object_class,
	                                  PROP_SERVICE,
	                                  NM_VPN_EDITOR_PLUGIN_SERVICE);
}

/*****************************************************************************/

G_MODULE_EXPORT NMVpnEditorPlugin *
nm_vpn_editor_plugin_factory (GError **error)
{
	g_return_val_if_fail (!error || !*error, NULL);

	bindtextdomain (GETTEXT_PACKAGE, LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");

	return g_object_new (WIREGUARD_TYPE_EDITOR_PLUGIN, NULL);
}

