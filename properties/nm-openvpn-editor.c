/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * CVSID: $Id: nm-openvpn.c 4232 2008-10-29 09:13:40Z tambeti $
 *
 * nm-openvpn.c : GNOME UI dialogs for configuring openvpn VPN connections
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

#include "nm-openvpn-editor.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>

#include "auth-helpers.h"
#include "utils.h"

/*****************************************************************************/

static void openvpn_editor_plugin_widget_interface_init (NMVpnEditorInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (OpenvpnEditor, openvpn_editor_plugin_widget, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR,
                                               openvpn_editor_plugin_widget_interface_init))

#define OPENVPN_EDITOR_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), OPENVPN_TYPE_EDITOR, OpenvpnEditorPrivate))

typedef struct {
	GtkBuilder *builder;
	GtkWidget *widget;
	GtkWindowGroup *window_group;
	gboolean window_added;
	GHashTable *advanced;
	gboolean new_connection;
	GtkWidget *tls_user_cert_chooser;
} OpenvpnEditorPrivate;

/*****************************************************************************/

#define COL_AUTH_NAME 0
#define COL_AUTH_PAGE 1
#define COL_AUTH_TYPE 2

static gboolean
check_gateway_entry (const char *str)
{
	gs_free char *str_clone = NULL;
	char *str_iter;
	const char *tok;
	gboolean success = FALSE;

	if (!str || !str[0])
		return FALSE;

	str_clone = g_strdup (str);
	str_iter = str_clone;
	while ((tok = strsep (&str_iter, " \t,"))) {
		if (   tok[0]
		    && (nmovpn_remote_parse (tok,
		                             NULL,
		                             NULL,
		                             NULL,
		                             NULL,
		                             NULL) != -1))
		   return FALSE;
		success = TRUE;
	}
	return success;
}

static gboolean
check_validity (OpenvpnEditor *self, GError **error)
{
	OpenvpnEditorPrivate *priv = OPENVPN_EDITOR_GET_PRIVATE (self);
	GtkWidget *widget;
	const char *str;
	GtkTreeModel *model;
	GtkTreeIter iter;
	const char *contype = NULL;
	gboolean success;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && check_gateway_entry (str))
		gtk_style_context_remove_class (gtk_widget_get_style_context (widget), "error");
	else {
		gtk_style_context_add_class (gtk_widget_get_style_context (widget), "error");
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
		             NM_OPENVPN_KEY_REMOTE);
		return FALSE;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "auth_combo"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	g_return_val_if_fail (model, FALSE);
	success = gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter);
	g_return_val_if_fail (success == TRUE, FALSE);
	gtk_tree_model_get (model, &iter, COL_AUTH_TYPE, &contype, -1);
	if (!auth_widget_check_validity (priv->builder, contype, error))
		return FALSE;

	return TRUE;
}

static void
stuff_changed_cb (GtkWidget *widget, gpointer user_data)
{
	g_signal_emit_by_name (OPENVPN_EDITOR (user_data), "changed");
}

static void
auth_combo_changed_cb (GtkWidget *combo, gpointer user_data)
{
	OpenvpnEditor *self = OPENVPN_EDITOR (user_data);
	OpenvpnEditorPrivate *priv = OPENVPN_EDITOR_GET_PRIVATE (self);
	GtkWidget *auth_notebook;
	GtkTreeModel *model;
	GtkTreeIter iter;
	gint new_page = 0;

	auth_notebook = GTK_WIDGET (gtk_builder_get_object (priv->builder, "auth_notebook"));
	g_assert (auth_notebook);

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (combo));
	g_assert (model);
	g_assert (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter));

	gtk_tree_model_get (model, &iter, COL_AUTH_PAGE, &new_page, -1);

	gtk_notebook_set_current_page (GTK_NOTEBOOK (auth_notebook), new_page);

	stuff_changed_cb (combo, self);
}

static void
advanced_dialog_close_cb (GtkWidget *dialog, gpointer user_data)
{
	gtk_widget_hide (dialog);
	/* gtk_widget_destroy() will remove the window from the window group */
	gtk_widget_destroy (dialog);
}

static void
advanced_dialog_response_cb (GtkWidget *dialog, gint response, gpointer user_data)
{
	OpenvpnEditor *self = OPENVPN_EDITOR (user_data);
	OpenvpnEditorPrivate *priv = OPENVPN_EDITOR_GET_PRIVATE (self);
	GError *error = NULL;

	if (response != GTK_RESPONSE_OK) {
		advanced_dialog_close_cb (dialog, self);
		return;
	}

	if (priv->advanced)
		g_hash_table_destroy (priv->advanced);
	priv->advanced = advanced_dialog_new_hash_from_dialog (dialog, &error);
	if (!priv->advanced) {
		g_message ("%s: error reading advanced settings: %s", __func__, error->message);
		g_error_free (error);
	}
	advanced_dialog_close_cb (dialog, self);

	stuff_changed_cb (NULL, self);
}

static void
advanced_button_clicked_cb (GtkWidget *button, gpointer user_data)
{
	OpenvpnEditor *self = OPENVPN_EDITOR (user_data);
	OpenvpnEditorPrivate *priv = OPENVPN_EDITOR_GET_PRIVATE (self);
	GtkWidget *dialog, *toplevel, *widget;
	GtkTreeModel *model;
	GtkTreeIter iter;
	const char *contype = NULL;
	gboolean success;

	toplevel = gtk_widget_get_toplevel (priv->widget);
	g_return_if_fail (gtk_widget_is_toplevel (toplevel));

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "auth_combo"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	success = gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter);
	g_return_if_fail (success == TRUE);
	gtk_tree_model_get (model, &iter, COL_AUTH_TYPE, &contype, -1);

	dialog = advanced_dialog_new (priv->advanced, contype);
	if (!dialog) {
		g_warning ("%s: failed to create the Advanced dialog!", __func__);
		return;
	}

	gtk_window_group_add_window (priv->window_group, GTK_WINDOW (dialog));
	if (!priv->window_added) {
		gtk_window_group_add_window (priv->window_group, GTK_WINDOW (toplevel));
		priv->window_added = TRUE;
	}

	gtk_window_set_transient_for (GTK_WINDOW (dialog), GTK_WINDOW (toplevel));
	g_signal_connect (G_OBJECT (dialog), "response", G_CALLBACK (advanced_dialog_response_cb), self);
	g_signal_connect (G_OBJECT (dialog), "close", G_CALLBACK (advanced_dialog_close_cb), self);

	gtk_widget_show_all (dialog);
}

static gboolean
init_editor_plugin (OpenvpnEditor *self, NMConnection *connection, GError **error)
{
	OpenvpnEditorPrivate *priv = OPENVPN_EDITOR_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	GtkWidget *widget;
	GtkListStore *store;
	GtkTreeIter iter;
	int active = -1;
	const char *value;
	const char *contype = NM_OPENVPN_CONTYPE_TLS;

	s_vpn = nm_connection_get_setting_vpn (connection);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "auth_combo"));
	g_return_val_if_fail (widget != NULL, FALSE);

	store = gtk_list_store_new (3, G_TYPE_STRING, G_TYPE_INT, G_TYPE_STRING);

	if (s_vpn) {
		contype = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE);
		if (contype) {
			if (   strcmp (contype, NM_OPENVPN_CONTYPE_TLS)
			    && strcmp (contype, NM_OPENVPN_CONTYPE_STATIC_KEY)
			    && strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD)
			    && strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD_TLS))
				contype = NM_OPENVPN_CONTYPE_TLS;
		} else
			contype = NM_OPENVPN_CONTYPE_TLS;
	}

	/* TLS auth widget */
		tls_pw_init_auth_widget (priv->builder, s_vpn,
	                         NM_OPENVPN_CONTYPE_TLS, "tls",
	                         stuff_changed_cb, self);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    COL_AUTH_NAME, _("Certificates (TLS)"),
	                    COL_AUTH_PAGE, 0,
	                    COL_AUTH_TYPE, NM_OPENVPN_CONTYPE_TLS,
	                    -1);

	/* Password auth widget */
	tls_pw_init_auth_widget (priv->builder, s_vpn,
	                         NM_OPENVPN_CONTYPE_PASSWORD, "pw",
	                         stuff_changed_cb, self);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    COL_AUTH_NAME, _("Password"),
	                    COL_AUTH_PAGE, 1,
	                    COL_AUTH_TYPE, NM_OPENVPN_CONTYPE_PASSWORD,
	                    -1);
	if ((active < 0) && !strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD))
		active = 1;

	/* Password+TLS auth widget */
	tls_pw_init_auth_widget (priv->builder, s_vpn,
	                         NM_OPENVPN_CONTYPE_PASSWORD_TLS, "pw_tls",
	                         stuff_changed_cb, self);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    COL_AUTH_NAME, _("Password with Certificates (TLS)"),
	                    COL_AUTH_PAGE, 2,
	                    COL_AUTH_TYPE, NM_OPENVPN_CONTYPE_PASSWORD_TLS,
	                    -1);
	if ((active < 0) && !strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD_TLS))
		active = 2;

	/* Static key auth widget */
	sk_init_auth_widget (priv->builder, s_vpn, stuff_changed_cb, self);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    COL_AUTH_NAME, _("Static Key"),
	                    COL_AUTH_PAGE, 3,
	                    COL_AUTH_TYPE, NM_OPENVPN_CONTYPE_STATIC_KEY,
	                    -1);
	if ((active < 0) && !strcmp (contype, NM_OPENVPN_CONTYPE_STATIC_KEY))
		active = 3;

	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	g_signal_connect (widget, "changed", G_CALLBACK (auth_combo_changed_cb), self);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? 0 : active);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "advanced_button"));
	g_signal_connect (G_OBJECT (widget), "clicked", G_CALLBACK (advanced_button_clicked_cb), self);

	return TRUE;
}

static GObject *
get_widget (NMVpnEditor *iface)
{
	OpenvpnEditor *self = OPENVPN_EDITOR (iface);
	OpenvpnEditorPrivate *priv = OPENVPN_EDITOR_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
}

static void
hash_copy_advanced (gpointer key, gpointer data, gpointer user_data)
{
	NMSettingVpn *s_vpn = NM_SETTING_VPN (user_data);
	const char *value = (const char *) data;

	g_return_if_fail (value && strlen (value));

	/* HTTP Proxy password is a secret, not a data item */
	if (!strcmp (key, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD))
		nm_setting_vpn_add_secret (s_vpn, (const char *) key, value);
	else
		nm_setting_vpn_add_data_item (s_vpn, (const char *) key, value);
}

static char *
get_auth_type (GtkBuilder *builder)
{
	GtkComboBox *combo;
	GtkTreeModel *model;
	GtkTreeIter iter;
	char *auth_type = NULL;
	gboolean success;

	combo = GTK_COMBO_BOX (GTK_WIDGET (gtk_builder_get_object (builder, "auth_combo")));
	model = gtk_combo_box_get_model (combo);

	success = gtk_combo_box_get_active_iter (combo, &iter);
	g_return_val_if_fail (success == TRUE, NULL);
	gtk_tree_model_get (model, &iter, COL_AUTH_TYPE, &auth_type, -1);

	return auth_type;
}

static gboolean
update_connection (NMVpnEditor *iface,
                   NMConnection *connection,
                   GError **error)
{
	OpenvpnEditor *self = OPENVPN_EDITOR (iface);
	OpenvpnEditorPrivate *priv = OPENVPN_EDITOR_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	GtkWidget *widget;
	char *auth_type;
	const char *str;
	gboolean valid = FALSE;

	if (!check_validity (self, error))
		return FALSE;

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_VPN_SERVICE_TYPE_OPENVPN, NULL);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && str[0])
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE, str);

	auth_type = get_auth_type (priv->builder);
	if (auth_type) {
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, auth_type);
		auth_widget_update_connection (priv->builder, auth_type, s_vpn);
		g_free (auth_type);
	}

	if (priv->advanced)
		g_hash_table_foreach (priv->advanced, hash_copy_advanced, s_vpn);

	/* Default to agent-owned secrets for new connections */
	if (priv->new_connection) {
		if (nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD)) {
			nm_setting_set_secret_flags (NM_SETTING (s_vpn),
			                             NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD,
			                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
			                             NULL);
		}

		if (nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD)) {
			nm_setting_set_secret_flags (NM_SETTING (s_vpn),
			                             NM_OPENVPN_KEY_PASSWORD,
			                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
			                             NULL);
		}

		if (nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS)) {
			nm_setting_set_secret_flags (NM_SETTING (s_vpn),
			                             NM_OPENVPN_KEY_CERTPASS,
			                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
			                             NULL);
		}
	}

	nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	valid = TRUE;

	return valid;
}

static void
is_new_func (const char *key, const char *value, gpointer user_data)
{
	gboolean *is_new = user_data;

	/* If there are any VPN data items the connection isn't new */
	*is_new = FALSE;
}

/*****************************************************************************/

static void
openvpn_editor_plugin_widget_init (OpenvpnEditor *plugin)
{
}

NMVpnEditor *
openvpn_editor_new (NMConnection *connection, GError **error)
{
	NMVpnEditor *object;
	OpenvpnEditorPrivate *priv;
	gboolean new = TRUE;
	NMSettingVpn *s_vpn;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	object = g_object_new (OPENVPN_TYPE_EDITOR, NULL);
	if (!object) {
		g_set_error_literal (error, NMV_EDITOR_PLUGIN_ERROR, 0, _("could not create openvpn object"));
		return NULL;
	}

	priv = OPENVPN_EDITOR_GET_PRIVATE (object);

	priv->builder = gtk_builder_new ();

	gtk_builder_set_translation_domain (priv->builder, GETTEXT_PACKAGE);

	if (!gtk_builder_add_from_resource (priv->builder, "/org/freedesktop/network-manager-openvpn/nm-openvpn-dialog.ui", error)) {
		g_object_unref (object);
		g_return_val_if_reached (NULL);
	}

	priv->widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "openvpn-vbox"));
	if (!priv->widget) {
		g_set_error_literal (error, NMV_EDITOR_PLUGIN_ERROR, 0, _("could not load UI widget"));
		g_object_unref (object);
		g_return_val_if_reached (NULL);
	}
	g_object_ref_sink (priv->widget);

	priv->window_group = gtk_window_group_new ();

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (s_vpn)
		nm_setting_vpn_foreach_data_item (s_vpn, is_new_func, &new);
	priv->new_connection = new;

	if (!init_editor_plugin (OPENVPN_EDITOR (object), connection, error)) {
		g_object_unref (object);
		return NULL;
	}

	priv->advanced = advanced_dialog_new_hash_from_connection (connection, error);
	if (!priv->advanced) {
		g_object_unref (object);
		return NULL;
	}

	return object;
}

static void
dispose (GObject *object)
{
	OpenvpnEditor *plugin = OPENVPN_EDITOR (object);
	OpenvpnEditorPrivate *priv = OPENVPN_EDITOR_GET_PRIVATE (plugin);

	g_clear_object (&priv->window_group);

	g_clear_object (&priv->widget);

	g_clear_object (&priv->builder);

	g_clear_pointer (&priv->advanced, g_hash_table_destroy);

	G_OBJECT_CLASS (openvpn_editor_plugin_widget_parent_class)->dispose (object);
}

static void
openvpn_editor_plugin_widget_interface_init (NMVpnEditorInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
}

static void
openvpn_editor_plugin_widget_class_init (OpenvpnEditorClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (OpenvpnEditorPrivate));

	object_class->dispose = dispose;
}

/*****************************************************************************/

#ifndef NM_VPN_OLD

#include "nm-openvpn-editor-plugin.h"

G_MODULE_EXPORT NMVpnEditor *
nm_vpn_editor_factory_openvpn (NMVpnEditorPlugin *editor_plugin,
                               NMConnection *connection,
                               GError **error)
{
	g_return_val_if_fail (!error || !*error, NULL);

	return openvpn_editor_new (connection, error);
}
#endif

