/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 *
 * Copyright (C) 2008 - 2010 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2008 - 2012 Red Hat, Inc.
 * Copyright (C) 2008 Tambet Ingo, <tambet@gmail.com>
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

#include "auth-helpers.h"

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#ifdef NM_VPN_OLD
#include <nm-cert-chooser.h>
#else
#include <nma-cert-chooser.h>
#endif

#include "utils.h"
#include "nm-utils/nm-shared-utils.h"

#define BLOCK_HANDLER_ID "block-handler-id"

/*****************************************************************************/

static const char *comp_lzo_values[] = {
	"adaptive",
	"yes",
	"no-by-default",
};

static const char *
comp_lzo_values_conf_coerce (const char *value_conf)
{
	if (!value_conf || nm_streq (value_conf, "no"))
		return NULL;
	if (nm_streq (value_conf, "yes"))
		return "yes";
	if (nm_streq (value_conf, "no-by-default"))
		return "no-by-default";
	return "adaptive";
}

static const char *
comp_lzo_values_conf_to_display (const char *value_conf)
{
	if (nm_streq (value_conf, "yes"))
		return "yes";
	if (nm_streq (value_conf, "no-by-default"))
		return "no";
	if (nm_streq (value_conf, "adaptive"))
		return "adaptive";
	g_return_val_if_reached ("adaptive");
}

/*****************************************************************************/

/* From gnome-control-center/panels/network/connection-editor/ui-helpers.c */

static void
widget_set_error (GtkWidget *widget)
{
	g_return_if_fail (GTK_IS_WIDGET (widget));

	gtk_style_context_add_class (gtk_widget_get_style_context (widget), "error");
}

static void
widget_unset_error (GtkWidget *widget)
{
	g_return_if_fail (GTK_IS_WIDGET (widget));

	gtk_style_context_remove_class (gtk_widget_get_style_context (widget), "error");
}


typedef struct {
	GtkWidget *widget1;
	GtkWidget *widget2;
} TlsChooserSignalData;

static void
tls_cert_changed_cb (NMACertChooser *this, gpointer user_data)
{
	NMACertChooser *other = user_data;
	NMSetting8021xCKScheme scheme;
	char *this_cert, *other_cert;
	char *this_key, *other_key;

	other_key = nma_cert_chooser_get_key (other, &scheme);
	this_key = nma_cert_chooser_get_key (this, &scheme);
	other_cert = nma_cert_chooser_get_cert (other, &scheme);
	this_cert = nma_cert_chooser_get_cert (this, &scheme);

	if (   scheme == NM_SETTING_802_1X_CK_SCHEME_PATH
	    && is_pkcs12 (this_cert)) {
		if (!this_key)
			nma_cert_chooser_set_key (this, this_cert, NM_SETTING_802_1X_CK_SCHEME_PATH);
		if (!other_cert) {
			nma_cert_chooser_set_cert (other, this_cert, NM_SETTING_802_1X_CK_SCHEME_PATH);
			if (!other_key)
				nma_cert_chooser_set_key (other, this_cert, NM_SETTING_802_1X_CK_SCHEME_PATH);
		}
	}

	g_free (this_cert);
	g_free (other_cert);
	g_free (this_key);
	g_free (other_key);
}

static void
tls_setup (GtkBuilder *builder,
           NMSettingVpn *s_vpn,
           const char *prefix,
           NMACertChooser *ca_chooser,
           ChangedCallback changed_cb,
           gpointer user_data)
{
	NMACertChooser *cert;
	const char *value;
	char *tmp;

	tmp = g_strdup_printf ("%s_user_cert", prefix);
	cert = NMA_CERT_CHOOSER (gtk_builder_get_object (builder, tmp));
	g_free (tmp);

	nma_cert_chooser_add_to_size_group (cert, GTK_SIZE_GROUP (gtk_builder_get_object (builder, "labels")));
	g_signal_connect (G_OBJECT (cert), "changed", G_CALLBACK (changed_cb), user_data);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CERT);
		if (value && strlen (value))
			nma_cert_chooser_set_cert (cert, value, NM_SETTING_802_1X_CK_SCHEME_PATH);

		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_KEY);
		if (value && strlen (value))
			nma_cert_chooser_set_key (cert, value, NM_SETTING_802_1X_CK_SCHEME_PATH);
		value = nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS);
		if (value)
			nma_cert_chooser_set_key_password (cert, value);
	}

	nma_cert_chooser_setup_key_password_storage (cert, 0, (NMSetting *) s_vpn,
	                                             NM_OPENVPN_KEY_CERTPASS, TRUE, FALSE);

	/* Link choosers to the PKCS#12 changer callback */
	g_signal_connect_object (ca_chooser, "changed", G_CALLBACK (tls_cert_changed_cb), cert, 0);
	g_signal_connect_object (cert, "changed", G_CALLBACK (tls_cert_changed_cb), ca_chooser, 0);
}

static void
pw_setup (GtkBuilder *builder,
          NMSettingVpn *s_vpn,
          const char *prefix,
          ChangedCallback changed_cb,
          gpointer user_data)
{
	GtkWidget *widget;
	const char *value;
	char *tmp;

	tmp = g_strdup_printf ("%s_username_entry", prefix);
	widget = GTK_WIDGET (gtk_builder_get_object (builder, tmp));
	g_free (tmp);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_USERNAME);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (changed_cb), user_data);

	/* Fill in the user password */
	tmp = g_strdup_printf ("%s_password_entry", prefix);
	widget = GTK_WIDGET (gtk_builder_get_object (builder, tmp));
	g_free (tmp);
	g_signal_connect (widget, "changed", G_CALLBACK (changed_cb), user_data);

	if (s_vpn) {
		value = nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}

	nma_utils_setup_password_storage (widget, 0, (NMSetting *) s_vpn, NM_OPENVPN_KEY_PASSWORD,
	                                  TRUE, FALSE);
}

void
tls_pw_init_auth_widget (GtkBuilder *builder,
                         NMSettingVpn *s_vpn,
                         const char *contype,
                         const char *prefix,
                         ChangedCallback changed_cb,
                         gpointer user_data)
{
	NMACertChooser *ca;
	const char *value;
	char *tmp;
	gboolean tls = FALSE, pw = FALSE;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (changed_cb != NULL);
	g_return_if_fail (prefix != NULL);

	tmp = g_strdup_printf ("%s_ca_cert", prefix);
	ca = NMA_CERT_CHOOSER (gtk_builder_get_object (builder, tmp));
	g_free (tmp);
	nma_cert_chooser_add_to_size_group (ca, GTK_SIZE_GROUP (gtk_builder_get_object (builder, "labels")));

	/* Three major connection types here: TLS-only, PW-only, and TLS + PW */
	if (!strcmp (contype, NM_OPENVPN_CONTYPE_TLS) || !strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD_TLS))
		tls = TRUE;
	if (!strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD) || !strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD_TLS))
		pw = TRUE;

	g_signal_connect (ca, "changed", G_CALLBACK (changed_cb), user_data);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CA);
		if (value && strlen (value))
			nma_cert_chooser_set_cert (ca, value, NM_SETTING_802_1X_CK_SCHEME_PATH);
	}

	/* Set up the rest of the options */
	if (tls)
		tls_setup (builder, s_vpn, prefix, ca, changed_cb, user_data);
	if (pw)
		pw_setup (builder, s_vpn, prefix, changed_cb, user_data);
}

#define SK_DIR_COL_NAME 0
#define SK_DIR_COL_NUM  1

void
sk_init_auth_widget (GtkBuilder *builder,
                     NMSettingVpn *s_vpn,
                     ChangedCallback changed_cb,
                     gpointer user_data)
{
	GtkWidget *widget;
	const char *value = NULL;
	GtkListStore *store;
	GtkTreeIter iter;
	gint active = -1;
	gint direction = -1;
	GtkFileFilter *filter;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (changed_cb != NULL);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_key_chooser"));
	filter = sk_file_chooser_filter_new ();
	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (widget), filter);
	gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER (widget), TRUE);
	gtk_file_chooser_button_set_title (GTK_FILE_CHOOSER_BUTTON (widget),
	                                   _("Choose an OpenVPN static key…"));
	g_signal_connect (G_OBJECT (widget), "selection-changed", G_CALLBACK (changed_cb), user_data);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY);
		if (value && strlen (value))
			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), value);
	}

	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_INT);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION);
		if (value && strlen (value)) {
			long int tmp;

			errno = 0;
			tmp = strtol (value, NULL, 10);
			if (errno == 0 && (tmp == 0 || tmp == 1))
				direction = (guint32) tmp;
		}
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, SK_DIR_COL_NAME, _("None"), SK_DIR_COL_NUM, -1, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, SK_DIR_COL_NAME, "0", SK_DIR_COL_NUM, 0, -1);
	if (direction == 0)
		active = 1;

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, SK_DIR_COL_NAME, "1", SK_DIR_COL_NUM, 1, -1);
	if (direction == 1)
		active = 2;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_direction_combo"));

	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? 0 : active);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_local_address_entry"));
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (changed_cb), user_data);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_remote_address_entry"));
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (changed_cb), user_data);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
}

static gboolean
validate_cert_chooser (GtkBuilder *builder, const char *name, GError **error)
{
	NMACertChooser *chooser;

	chooser = NMA_CERT_CHOOSER (gtk_builder_get_object (builder, name));
	return nma_cert_chooser_validate (chooser, error);
}

static gboolean
validate_tls (GtkBuilder *builder, const char *prefix, GError **error)
{
	char *tmp;
	gboolean valid, encrypted = FALSE;
	NMACertChooser *user_cert;
	NMSettingSecretFlags pw_flags;
	gboolean secrets_required = TRUE;
	NMSetting8021xCKScheme scheme;
	GError *local = NULL;

	tmp = g_strdup_printf ("%s_ca_cert", prefix);
	valid = validate_cert_chooser (builder, tmp, &local);
	g_free (tmp);
	if (!valid) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
		             "%s: %s", NM_OPENVPN_KEY_CA, local->message);
		g_error_free (local);
		return FALSE;
	}

	tmp = g_strdup_printf ("%s_user_cert", prefix);
	user_cert = NMA_CERT_CHOOSER (gtk_builder_get_object (builder, tmp));
	valid = validate_cert_chooser (builder, tmp, &local);
	g_free (tmp);
	if (!valid) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
		             "%s: %s", NM_OPENVPN_KEY_CERT, local->message);
		g_error_free (local);
		return FALSE;
	}

	/* Encrypted certificates require a password */
	tmp = nma_cert_chooser_get_cert (user_cert, &scheme);
	encrypted = is_encrypted (tmp);
	g_free (tmp);

	pw_flags = nma_cert_chooser_get_key_password_flags (user_cert);
	if (   pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED
	    || pw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
		secrets_required = FALSE;

	if (encrypted && secrets_required) {
		if (!nma_cert_chooser_get_key_password (user_cert)) {
			g_set_error (error,
			             NMV_EDITOR_PLUGIN_ERROR,
			             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
			             NM_OPENVPN_KEY_CERTPASS);
			return FALSE;
		}
	}

	return TRUE;
}

gboolean
auth_widget_check_validity (GtkBuilder *builder, const char *contype, GError **error)
{
	GtkWidget *widget;
	const char *str;
	char *filename;
	GError *local = NULL;

	if (!strcmp (contype, NM_OPENVPN_CONTYPE_TLS)) {
		if (!validate_tls (builder, "tls", error))
			return FALSE;
	} else if (!strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
		if (!validate_tls (builder, "pw_tls", error))
			return FALSE;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "pw_tls_username_entry"));
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (!str || !strlen (str)) {
			g_set_error (error,
			             NMV_EDITOR_PLUGIN_ERROR,
			             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
			             NM_OPENVPN_KEY_USERNAME);
			return FALSE;
		}
	} else if (!strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD)) {
		if (!validate_cert_chooser (builder, "pw_ca_cert", &local)) {
			g_set_error (error,
			             NMV_EDITOR_PLUGIN_ERROR,
			             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
			             "%s: %s", NM_OPENVPN_KEY_CA, local->message);
			g_error_free (local);
			return FALSE;
		}
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "pw_username_entry"));
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (!str || !strlen (str)) {
			g_set_error (error,
			             NMV_EDITOR_PLUGIN_ERROR,
			             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
			             NM_OPENVPN_KEY_USERNAME);
			return FALSE;
		}
	} else if (!strcmp (contype, NM_OPENVPN_CONTYPE_STATIC_KEY)) {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_key_chooser"));
		filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
		if (!filename || !filename[0]) {
			g_free (filename);
			g_set_error (error,
			             NMV_EDITOR_PLUGIN_ERROR,
			             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
			             NM_OPENVPN_KEY_STATIC_KEY);
			return FALSE;
		}
		g_free (filename);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_local_address_entry"));
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (!str || !strlen (str)) {
			g_set_error (error,
			             NMV_EDITOR_PLUGIN_ERROR,
			             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
			             NM_OPENVPN_KEY_LOCAL_IP);
			return FALSE;
		}

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_remote_address_entry"));
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (!str || !strlen (str)) {
			g_set_error (error,
			             NMV_EDITOR_PLUGIN_ERROR,
			             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
			             NM_OPENVPN_KEY_REMOTE_IP);
			return FALSE;
		}
	} else
		g_assert_not_reached ();

	return TRUE;
}

static void
update_from_cert_chooser (GtkBuilder *builder,
                          const char *cert_prop,
                          const char *key_prop,
                          const char *key_pass_prop,
                          const char *prefix,
                          const char *widget_name,
                          NMSettingVpn *s_vpn)
{
	NMSetting8021xCKScheme scheme;
	NMACertChooser *cert_chooser;
	NMSettingSecretFlags pw_flags;
	char *tmp;
	const char *password;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (cert_prop != NULL);
	g_return_if_fail (prefix != NULL);
	g_return_if_fail (widget_name != NULL);
	g_return_if_fail (s_vpn != NULL);

	tmp = g_strdup_printf ("%s_%s", prefix, widget_name);
	cert_chooser = NMA_CERT_CHOOSER (gtk_builder_get_object (builder, tmp));
	g_free (tmp);

	tmp = nma_cert_chooser_get_cert (cert_chooser, &scheme);
	if (tmp && strlen (tmp))
		nm_setting_vpn_add_data_item (s_vpn, cert_prop, tmp);
	g_free (tmp);

	if (key_prop) {
		g_return_if_fail (key_pass_prop != NULL);

		tmp = nma_cert_chooser_get_key (cert_chooser, &scheme);
		if (tmp && strlen (tmp))
			nm_setting_vpn_add_data_item (s_vpn, key_prop, tmp);
		g_free (tmp);

		password = nma_cert_chooser_get_key_password (cert_chooser);
		if (password && strlen (password))
			nm_setting_vpn_add_secret (s_vpn, key_pass_prop, password);

		pw_flags = nma_cert_chooser_get_key_password_flags (cert_chooser);
		nm_setting_set_secret_flags (NM_SETTING (s_vpn), key_pass_prop, pw_flags, NULL);
	}
}

static void
update_tls (GtkBuilder *builder, const char *prefix, NMSettingVpn *s_vpn)
{
	update_from_cert_chooser (builder,
	                          NM_OPENVPN_KEY_CA,
	                          NULL,
	                          NULL,
	                          prefix, "ca_cert", s_vpn);

	update_from_cert_chooser (builder,
	                          NM_OPENVPN_KEY_CERT,
	                          NM_OPENVPN_KEY_KEY,
	                          NM_OPENVPN_KEY_CERTPASS,
	                          prefix, "user_cert", s_vpn);
}

static void
update_pw (GtkBuilder *builder, const char *prefix, NMSettingVpn *s_vpn)
{
	GtkWidget *widget;
	NMSettingSecretFlags pw_flags;
	char *tmp;
	const char *str;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (prefix != NULL);
	g_return_if_fail (s_vpn != NULL);

	tmp = g_strdup_printf ("%s_username_entry", prefix);
	widget = GTK_WIDGET (gtk_builder_get_object (builder, tmp));
	g_free (tmp);

	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_USERNAME, str);

	/* Password */
	tmp = g_strdup_printf ("%s_password_entry", prefix);
	widget = (GtkWidget *) gtk_builder_get_object (builder, tmp);
	g_assert (widget);
	g_free (tmp);

	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD, str);

	/* Update password flags */
	pw_flags = nma_utils_menu_to_secret_flags (widget);
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), NM_OPENVPN_KEY_PASSWORD, pw_flags, NULL);
}

gboolean
auth_widget_update_connection (GtkBuilder *builder,
                               const char *contype,
                               NMSettingVpn *s_vpn)
{
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkWidget *widget;
	const char *str;
	char *filename;

	if (!strcmp (contype, NM_OPENVPN_CONTYPE_TLS)) {
		update_tls (builder, "tls", s_vpn);
	} else if (!strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD)) {
		update_from_cert_chooser (builder, NM_OPENVPN_KEY_CA, NULL, NULL,
		                          "pw", "ca_cert", s_vpn);
		update_pw (builder, "pw", s_vpn);
	} else if (!strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
		update_tls (builder, "pw_tls", s_vpn);
		update_pw (builder, "pw_tls", s_vpn);
	} else if (!strcmp (contype, NM_OPENVPN_CONTYPE_STATIC_KEY)) {
		/* Update static key */
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_key_chooser"));
		filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
		if (filename && strlen (filename))
			nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, filename);
		g_free (filename);

		/* Update direction */
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_direction_combo"));
		g_assert (widget);
		model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
		if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
			int direction = -1;

			gtk_tree_model_get (model, &iter, SK_DIR_COL_NUM, &direction, -1);
			if (direction > -1) {
				char *tmp = g_strdup_printf ("%d", direction);
				nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, tmp);
				g_free (tmp);
			}
		}

		/* Update local address */
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_local_address_entry"));
		g_assert (widget);
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (str && strlen (str))
			nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, str);

		/* Update remote address */
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_remote_address_entry"));
		g_assert (widget);
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (str && strlen (str))
			nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, str);
	} else
		g_assert_not_reached ();

	return TRUE;
}

static const char *
find_tag (const char *tag, const char *buf, gsize len)
{
	gsize i, taglen;

	taglen = strlen (tag);
	if (len < taglen)
		return NULL;

	for (i = 0; i < len - taglen + 1; i++) {
		if (memcmp (buf + i, tag, taglen) == 0)
			return buf + i;
	}
	return NULL;
}

static const char *sk_key_begin = "-----BEGIN OpenVPN Static key V1-----";

static gboolean
sk_default_filter (const GtkFileFilterInfo *filter_info, gpointer data)
{
	int fd;
	unsigned char buffer[1024];
	ssize_t bytes_read;
	gboolean show = FALSE;
	char *p;
	char *ext;

	if (!filter_info->filename)
		return FALSE;

	p = strrchr (filter_info->filename, '.');
	if (!p)
		return FALSE;

	ext = g_ascii_strdown (p, -1);
	if (!ext)
		return FALSE;
	if (!g_str_has_suffix (ext, ".key")) {
		g_free (ext);
		return FALSE;
	}
	g_free (ext);

	fd = open (filter_info->filename, O_RDONLY);
	if (fd < 0)
		return FALSE;

	bytes_read = read (fd, buffer, sizeof (buffer) - 1);
	if (bytes_read < 400)  /* needs to be lower? */
		goto out;
	buffer[bytes_read] = '\0';

	/* Check for PEM signatures */
	if (find_tag (sk_key_begin, (const char *) buffer, bytes_read)) {
		show = TRUE;
		goto out;
	}

out:
	close (fd);
	return show;
}

GtkFileFilter *
sk_file_chooser_filter_new (void)
{
	GtkFileFilter *filter;

	filter = gtk_file_filter_new ();
	gtk_file_filter_add_custom (filter, GTK_FILE_FILTER_FILENAME, sk_default_filter, NULL, NULL);
	gtk_file_filter_set_name (filter, _("OpenVPN Static Keys (*.key)"));
	return filter;
}

static const char *advanced_keys[] = {
	NM_OPENVPN_KEY_PORT,
	NM_OPENVPN_KEY_COMP_LZO,
	NM_OPENVPN_KEY_MSSFIX,
	NM_OPENVPN_KEY_FLOAT,
	NM_OPENVPN_KEY_TUNNEL_MTU,
	NM_OPENVPN_KEY_FRAGMENT_SIZE,
	NM_OPENVPN_KEY_TAP_DEV,
	NM_OPENVPN_KEY_DEV,
	NM_OPENVPN_KEY_DEV_TYPE,
	NM_OPENVPN_KEY_PROTO_TCP,
	NM_OPENVPN_KEY_PROXY_TYPE,
	NM_OPENVPN_KEY_PROXY_SERVER,
	NM_OPENVPN_KEY_PROXY_PORT,
	NM_OPENVPN_KEY_PROXY_RETRY,
	NM_OPENVPN_KEY_HTTP_PROXY_USERNAME,
	NM_OPENVPN_KEY_CIPHER,
	NM_OPENVPN_KEY_KEYSIZE,
	NM_OPENVPN_KEY_AUTH,
	NM_OPENVPN_KEY_TA_DIR,
	NM_OPENVPN_KEY_TA,
	NM_OPENVPN_KEY_TLS_CRYPT,
	NM_OPENVPN_KEY_RENEG_SECONDS,
	NM_OPENVPN_KEY_TLS_REMOTE,
	NM_OPENVPN_KEY_VERIFY_X509_NAME,
	NM_OPENVPN_KEY_REMOTE_RANDOM,
	NM_OPENVPN_KEY_TUN_IPV6,
	NM_OPENVPN_KEY_REMOTE_CERT_TLS,
	NM_OPENVPN_KEY_NS_CERT_TYPE,
	NM_OPENVPN_KEY_PING,
	NM_OPENVPN_KEY_PING_EXIT,
	NM_OPENVPN_KEY_PING_RESTART,
	NM_OPENVPN_KEY_MAX_ROUTES,
	NM_OPENVPN_KEY_MTU_DISC,
	NULL
};

static void
copy_values (const char *key, const char *value, gpointer user_data)
{
	GHashTable *hash = (GHashTable *) user_data;
	const char **i;

	for (i = &advanced_keys[0]; *i; i++) {
		if (strcmp (key, *i))
			continue;

		g_hash_table_insert (hash, g_strdup (key), g_strdup (value));
	}
}

GHashTable *
advanced_dialog_new_hash_from_connection (NMConnection *connection,
                                          GError **error)
{
	GHashTable *hash;
	NMSettingVpn *s_vpn;
	const char *secret, *flags;

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	s_vpn = nm_connection_get_setting_vpn (connection);
	nm_setting_vpn_foreach_data_item (s_vpn, copy_values, hash);

	/* HTTP Proxy password is special */
	secret = nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD);
	if (secret) {
		g_hash_table_insert (hash,
		                     g_strdup (NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD),
		                     g_strdup (secret));
	}
	flags = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD"-flags");
	if (flags)
		g_hash_table_insert (hash,
		                     g_strdup (NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD"-flags"),
		                     g_strdup (flags));

	return hash;
}

static void
checkbox_toggled_update_widget_cb (GtkWidget *check, gpointer user_data)
{
	GtkWidget *widget = (GtkWidget*) user_data;

	gtk_widget_set_sensitive (widget, gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (check)));
}

static const char *
nm_find_openvpn (void)
{
	static const char *openvpn_binary_paths[] = {
		"/usr/sbin/openvpn",
		"/sbin/openvpn",
		NULL
	};
	const char  **openvpn_binary = openvpn_binary_paths;

	while (*openvpn_binary != NULL) {
		if (g_file_test (*openvpn_binary, G_FILE_TEST_EXISTS))
			break;
		openvpn_binary++;
	}

	return *openvpn_binary;
}

#define TLS_CIPHER_COL_NAME 0
#define TLS_CIPHER_COL_DEFAULT 1

static void
populate_cipher_combo (GtkComboBox *box, const char *user_cipher)
{
	GtkListStore *store;
	GtkTreeIter iter;
	const char *openvpn_binary = NULL;
	gchar *tmp, **items, **item;
	gboolean user_added = FALSE;
	char *argv[3];
	GError *error = NULL;
	gboolean success, ignore_lines = TRUE;

	openvpn_binary = nm_find_openvpn ();
	if (!openvpn_binary)
		return;

	argv[0] = (char *) openvpn_binary;
	argv[1] = "--show-ciphers";
	argv[2] = NULL;

	success = g_spawn_sync ("/", argv, NULL, 0, NULL, NULL, &tmp, NULL, NULL, &error);
	if (!success) {
		g_warning ("%s: couldn't determine ciphers: %s", __func__, error->message);
		g_error_free (error);
		return;
	}

	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_INT);
	gtk_combo_box_set_model (box, GTK_TREE_MODEL (store));

	/* Add default option which won't pass --cipher to openvpn */
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    TLS_CIPHER_COL_NAME, _("Default"),
	                    TLS_CIPHER_COL_DEFAULT, TRUE, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    TLS_CIPHER_COL_NAME, "none",
	                    TLS_CIPHER_COL_DEFAULT, FALSE, -1);
	if (g_strcmp0 (user_cipher, "none") == 0) {
		gtk_combo_box_set_active_iter (box, &iter);
		user_added = TRUE;
	}

	items = g_strsplit (tmp, "\n", 0);
	g_free (tmp);

	for (item = items; *item; item++) {
		char *space;

		/* Don't add anything until after the first blank line. Also,
		 * any blank line indicates the start of a comment, ended by
		 * another blank line.
		 */
		if (!strlen (*item)) {
			ignore_lines = !ignore_lines;
			continue;
		}

		if (ignore_lines)
			continue;

		space = strchr (*item, ' ');
		if (space)
			*space = '\0';

		if (strcmp (*item, "none") == 0)
			continue;

		if (strlen (*item)) {
			gtk_list_store_append (store, &iter);
			gtk_list_store_set (store, &iter,
			                    TLS_CIPHER_COL_NAME, *item,
			                    TLS_CIPHER_COL_DEFAULT, FALSE, -1);
			if (!user_added && user_cipher && !g_ascii_strcasecmp (*item, user_cipher)) {
				gtk_combo_box_set_active_iter (box, &iter);
				user_added = TRUE;
			}
		}
	}

	/* Add the user-specified cipher if it exists wasn't found by openvpn */
	if (user_cipher && !user_added) {
		gtk_list_store_insert (store, &iter, 1);
		gtk_list_store_set (store, &iter,
		                    TLS_CIPHER_COL_NAME, user_cipher,
		                    TLS_CIPHER_COL_DEFAULT, FALSE, -1);
		gtk_combo_box_set_active_iter (box, &iter);
	} else if (!user_added) {
		gtk_combo_box_set_active (box, 0);
	}

	g_object_unref (G_OBJECT (store));
	g_strfreev (items);
}

#define HMACAUTH_COL_NAME 0
#define HMACAUTH_COL_VALUE 1
#define HMACAUTH_COL_DEFAULT 2

static void
populate_hmacauth_combo (GtkComboBox *box, const char *hmacauth)
{
	GtkListStore *store;
	GtkTreeIter iter;
	gboolean active_initialized = FALSE;
	const char **item;
	static const char *items[] = {
		NM_OPENVPN_AUTH_NONE,
		NM_OPENVPN_AUTH_RSA_MD4,
		NM_OPENVPN_AUTH_MD5,
		NM_OPENVPN_AUTH_SHA1,
		NM_OPENVPN_AUTH_SHA224,
		NM_OPENVPN_AUTH_SHA256,
		NM_OPENVPN_AUTH_SHA384,
		NM_OPENVPN_AUTH_SHA512,
		NM_OPENVPN_AUTH_RIPEMD160,
		NULL
	};

	store = gtk_list_store_new (3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_BOOLEAN);
	gtk_combo_box_set_model (box, GTK_TREE_MODEL (store));

	/* Add default option which won't pass --auth to openvpn */
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    HMACAUTH_COL_NAME, _("Default"),
	                    HMACAUTH_COL_DEFAULT, TRUE, -1);

	/* Add options */
	for (item = items; *item; item++) {
		const char *name = NULL;

		if (!strcmp (*item, NM_OPENVPN_AUTH_NONE))
			name = _("None");
		else if (!strcmp (*item, NM_OPENVPN_AUTH_RSA_MD4))
			name = _("RSA MD-4");
		else if (!strcmp (*item, NM_OPENVPN_AUTH_MD5))
			name = _("MD-5");
		else if (!strcmp (*item, NM_OPENVPN_AUTH_SHA1))
			name = _("SHA-1");
		else if (!strcmp (*item, NM_OPENVPN_AUTH_SHA224))
			name = _("SHA-224");
		else if (!strcmp (*item, NM_OPENVPN_AUTH_SHA256))
			name = _("SHA-256");
		else if (!strcmp (*item, NM_OPENVPN_AUTH_SHA384))
			name = _("SHA-384");
		else if (!strcmp (*item, NM_OPENVPN_AUTH_SHA512))
			name = _("SHA-512");
		else if (!strcmp (*item, NM_OPENVPN_AUTH_RIPEMD160))
			name = _("RIPEMD-160");
		else
			g_assert_not_reached ();

		gtk_list_store_append (store, &iter);
		gtk_list_store_set (store, &iter,
		                    HMACAUTH_COL_NAME, name,
		                    HMACAUTH_COL_VALUE, *item,
		                    HMACAUTH_COL_DEFAULT, FALSE, -1);
		if (hmacauth && !g_ascii_strcasecmp (*item, hmacauth)) {
			gtk_combo_box_set_active_iter (box, &iter);
			active_initialized = TRUE;
		}
	}

	if (!active_initialized)
		gtk_combo_box_set_active (box, 0);

	g_object_unref (store);
}

#define TLS_REMOTE_MODE_NONE        "none"
#define TLS_REMOTE_MODE_SUBJECT     NM_OPENVPN_VERIFY_X509_NAME_TYPE_SUBJECT
#define TLS_REMOTE_MODE_NAME        NM_OPENVPN_VERIFY_X509_NAME_TYPE_NAME
#define TLS_REMOTE_MODE_NAME_PREFIX NM_OPENVPN_VERIFY_X509_NAME_TYPE_NAME_PREFIX
#define TLS_REMOTE_MODE_LEGACY      "legacy"

#define TLS_REMOTE_MODE_COL_NAME 0
#define TLS_REMOTE_MODE_COL_VALUE 1

static void
populate_tls_remote_mode_entry_combo (GtkEntry* entry, GtkComboBox *box,
                                      const char *tls_remote, const char *x509_name)
{
	GtkListStore *store;
	GtkTreeIter iter;
	const char *subject_name = NULL;

	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_STRING);
	gtk_combo_box_set_model (box, GTK_TREE_MODEL (store));

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    TLS_REMOTE_MODE_COL_NAME, _("Don’t verify certificate identification"),
	                    TLS_REMOTE_MODE_COL_VALUE, TLS_REMOTE_MODE_NONE,
	                    -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    TLS_REMOTE_MODE_COL_NAME, _("Verify whole subject exactly"),
	                    TLS_REMOTE_MODE_COL_VALUE, TLS_REMOTE_MODE_SUBJECT,
	                    -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    TLS_REMOTE_MODE_COL_NAME, _("Verify name exactly"),
	                    TLS_REMOTE_MODE_COL_VALUE, TLS_REMOTE_MODE_NAME,
	                    -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    TLS_REMOTE_MODE_COL_NAME, _("Verify name by prefix"),
	                    TLS_REMOTE_MODE_COL_VALUE, TLS_REMOTE_MODE_NAME_PREFIX,
	                    -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    TLS_REMOTE_MODE_COL_NAME, _("Verify subject partially (legacy mode, strongly discouraged)"),
	                    TLS_REMOTE_MODE_COL_VALUE, TLS_REMOTE_MODE_LEGACY,
	                    -1);

	if (x509_name && strlen (x509_name)) {
		if (g_str_has_prefix (x509_name, "name:"))
			gtk_combo_box_set_active (box, 2);
		else if (g_str_has_prefix (x509_name, "name-prefix:"))
			gtk_combo_box_set_active (box, 3);
		else
			gtk_combo_box_set_active (box, 1);

		subject_name = strchr (x509_name, ':');
		if (subject_name)
			subject_name++;
		else
			subject_name = x509_name;
	} else if (tls_remote && strlen (tls_remote)) {
		gtk_combo_box_set_active (box, 4);

		subject_name = tls_remote;
	} else {
		gtk_combo_box_set_active (box, 0);

		subject_name = "";
	}

	gtk_entry_set_text (entry, subject_name);

    g_object_unref (store);
}

static void
tls_remote_changed (GtkWidget *widget, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *entry, *combo, *ok_button;
	GtkTreeIter iter;
	gboolean entry_enabled = TRUE, entry_has_error = FALSE;
	gboolean legacy_tls_remote = FALSE;

	entry     = GTK_WIDGET (gtk_builder_get_object (builder, "tls_remote_entry"));
	combo     = GTK_WIDGET (gtk_builder_get_object (builder, "tls_remote_mode_combo"));
	ok_button = GTK_WIDGET (gtk_builder_get_object (builder, "ok_button"));

	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter)) {
		gs_free char *tls_remote_mode = NULL;
		GtkTreeModel *combo_model = gtk_combo_box_get_model (GTK_COMBO_BOX (combo));

		gtk_tree_model_get (combo_model, &iter, TLS_REMOTE_MODE_COL_VALUE, &tls_remote_mode, -1);
		g_return_if_fail (tls_remote_mode);

		/* If a mode of 'none' is selected, disable the subject entry control.
		   Otherwise, enable the entry, and set up it's error state based on
		   whether it is empty or not (it should not be). */
		if (!strcmp (tls_remote_mode, TLS_REMOTE_MODE_NONE)) {
			entry_enabled = FALSE;
		} else {
			const char *subject = gtk_entry_get_text (GTK_ENTRY (entry));

			entry_enabled = TRUE;
			entry_has_error = !subject || !subject[0];
			legacy_tls_remote = nm_streq (tls_remote_mode, TLS_REMOTE_MODE_LEGACY);
		}
	}

	gtk_widget_set_sensitive (entry, entry_enabled);
	if(entry_has_error) {
		widget_set_error (entry);
		gtk_widget_set_sensitive (ok_button, FALSE);
	} else {
		if (legacy_tls_remote) {
			/* selecting tls-remote is not an error, but strongly discouraged. I wish
			 * there would be a warning-class as well. Anyway, mark the widget as
			 * erroneous, although this doesn't make the connection invalid (which
			 * is an ugly inconsistency). */
			widget_set_error (entry);
		} else
			widget_unset_error (entry);
		gtk_widget_set_sensitive (ok_button, TRUE);
	}

}

static void
remote_tls_cert_toggled_cb (GtkWidget *widget, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	gboolean use_remote_cert_tls = FALSE;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_cert_tls_checkbutton"));
	use_remote_cert_tls = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_cert_tls_label"));
	gtk_widget_set_sensitive (widget, use_remote_cert_tls);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_cert_tls_combo"));
	gtk_widget_set_sensitive (widget, use_remote_cert_tls);
}

#define REMOTE_CERT_COL_NAME 0
#define REMOTE_CERT_COL_VALUE 1

static void
populate_remote_cert_tls_combo (GtkComboBox *box, const char *remote_cert)
{
	GtkListStore *store;
	GtkTreeIter iter;

	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_STRING);
	gtk_combo_box_set_model (box, GTK_TREE_MODEL (store));

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    REMOTE_CERT_COL_NAME, _("Server"),
	                    REMOTE_CERT_COL_VALUE, NM_OPENVPN_REM_CERT_TLS_SERVER,
	                    -1);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    REMOTE_CERT_COL_NAME, _("Client"),
	                    REMOTE_CERT_COL_VALUE, NM_OPENVPN_REM_CERT_TLS_CLIENT,
	                    -1);

	if (g_strcmp0 (remote_cert, NM_OPENVPN_REM_CERT_TLS_CLIENT) == 0)
		gtk_combo_box_set_active (box, 1);
	else
		gtk_combo_box_set_active (box, 0);

	g_object_unref (store);
}

#define TLS_AUTH_MODE_NONE  0
#define TLS_AUTH_MODE_AUTH  1
#define TLS_AUTH_MODE_CRYPT 2

static void
tls_auth_toggled_cb (GtkWidget *widget, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	gint active;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_auth_mode"));
	active = gtk_combo_box_get_active (GTK_COMBO_BOX (widget));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "direction_label"));
	gtk_widget_set_sensitive (widget, active == TLS_AUTH_MODE_AUTH);
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "direction_combo"));
	gtk_widget_set_sensitive (widget, active == TLS_AUTH_MODE_AUTH);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_auth_label"));
	gtk_widget_set_sensitive (widget, active != TLS_AUTH_MODE_NONE);
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_auth_chooser"));
	gtk_widget_set_sensitive (widget, active != TLS_AUTH_MODE_NONE);
}

static void
ns_cert_type_toggled_cb (GtkWidget *widget, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	gboolean use_ns_cert_type = FALSE;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ns_cert_type_checkbutton"));
	use_ns_cert_type = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ns_cert_type_label"));
	gtk_widget_set_sensitive (widget, use_ns_cert_type);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ns_cert_type_combo"));
	gtk_widget_set_sensitive (widget, use_ns_cert_type);
}

#define NS_CERT_TYPE_COL_NAME 0
#define NS_CERT_TYPE_COL_VALUE 1

static void
populate_ns_cert_type_combo (GtkComboBox *box, const char *type)
{
	GtkListStore *store;
	GtkTreeIter iter;

	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_STRING);
	gtk_combo_box_set_model (box, GTK_TREE_MODEL (store));

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    NS_CERT_TYPE_COL_NAME, _("Server"),
	                    NS_CERT_TYPE_COL_VALUE, NM_OPENVPN_NS_CERT_TYPE_SERVER,
	                    -1);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    NS_CERT_TYPE_COL_NAME, _("Client"),
	                    NS_CERT_TYPE_COL_VALUE, NM_OPENVPN_NS_CERT_TYPE_CLIENT,
	                    -1);

	if (g_strcmp0 (type, NM_OPENVPN_NS_CERT_TYPE_CLIENT) == 0)
		gtk_combo_box_set_active (box, 1);
	else
		gtk_combo_box_set_active (box, 0);

	g_object_unref (store);
}

static void
mtu_disc_toggled_cb (GtkWidget *widget, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	gboolean use_mtu_disc;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "mtu_disc_checkbutton"));
	use_mtu_disc = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "mtu_disc_combo"));
	gtk_widget_set_sensitive (widget, use_mtu_disc);
}

#define PROXY_TYPE_NONE  0
#define PROXY_TYPE_HTTP  1
#define PROXY_TYPE_SOCKS 2

#define DEVICE_TYPE_IDX_TUN     0
#define DEVICE_TYPE_IDX_TAP     1

#define PING_EXIT    0
#define PING_RESTART 1

static void
proxy_type_changed (GtkComboBox *combo, gpointer user_data)
{
	GtkBuilder *builder = GTK_BUILDER (user_data);
	gboolean sensitive;
	GtkWidget *widget;
	guint32 i = 0;
	int active;
	const char *widgets[] = {
		"proxy_desc_label", "proxy_server_label", "proxy_server_entry",
		"proxy_port_label", "proxy_port_spinbutton", "proxy_retry_checkbutton",
		"proxy_username_label", "proxy_password_label", "proxy_username_entry",
		"proxy_password_entry", "show_proxy_password", NULL
	};
	const char *user_pass_widgets[] = {
		"proxy_username_label", "proxy_password_label", "proxy_username_entry",
		"proxy_password_entry", "show_proxy_password", NULL
	};

	active = gtk_combo_box_get_active (combo);
	sensitive = (active > PROXY_TYPE_NONE);

	while (widgets[i]) {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, widgets[i++]));
		gtk_widget_set_sensitive (widget, sensitive);
	}

	/* Additionally user/pass widgets need to be disabled for SOCKS */
	if (active == PROXY_TYPE_SOCKS) {
		i = 0;
		while (user_pass_widgets[i]) {
			widget = GTK_WIDGET (gtk_builder_get_object (builder, user_pass_widgets[i++]));
			gtk_widget_set_sensitive (widget, FALSE);
		}
	}

	/* Proxy options require TCP; but don't reset the TCP checkbutton
	 * to false when the user disables HTTP proxy; leave it checked.
	 */
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tcp_checkbutton"));
	if (sensitive == TRUE)
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	gtk_widget_set_sensitive (widget, !sensitive);
}

static void
show_proxy_password_toggled_cb (GtkCheckButton *button, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *widget;
	gboolean visible;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_password_entry"));
	g_assert (widget);

	visible = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (button));
	gtk_entry_set_visibility (GTK_ENTRY (widget), visible);
}

static void
device_name_filter_cb (GtkEntry *entry,
                       const gchar *text,
                       gint length,
                       gint *position,
                       void *user_data)
{
	int i, count = 0;
	gchar *result = g_new (gchar, length + 1);
	GtkEditable *editable = GTK_EDITABLE (entry);

	for (i = 0; i < length; i++) {
		if (text[i] == '/' || g_ascii_isspace (text[i]))
			continue;
		result[count++] = text[i];
	}
	result[count] = 0;

	if (count > 0) {
		g_signal_handlers_block_by_func (G_OBJECT (editable),
		                                 G_CALLBACK (device_name_filter_cb),
		                                 user_data);
		gtk_editable_insert_text (editable, result, count, position);
		g_signal_handlers_unblock_by_func (G_OBJECT (editable),
		                                   G_CALLBACK (device_name_filter_cb),
		                                   user_data);
	}
	g_signal_stop_emission_by_name (G_OBJECT (editable), "insert-text");

	g_free (result);
}

static gboolean
device_name_changed_cb (GtkEntry *entry,
                        gpointer user_data)
{
	GtkEditable *editable = GTK_EDITABLE (entry);
	GtkWidget *ok_button = user_data;
	gboolean entry_sensitive;
	char *entry_text;

	entry_sensitive = gtk_widget_get_sensitive (GTK_WIDGET (entry));
	entry_text = gtk_editable_get_chars (editable, 0, -1);

	/* Change cell's background to red if the value is invalid */
	if (   entry_sensitive
	    && entry_text[0] != '\0'
	    && !_nm_utils_is_valid_iface_name (entry_text)) {
		widget_set_error (GTK_WIDGET (editable));
		gtk_widget_set_sensitive (ok_button, FALSE);
	} else {
		widget_unset_error (GTK_WIDGET (editable));
		gtk_widget_set_sensitive (ok_button, TRUE);
	}

	g_free (entry_text);
	return FALSE;
}

static void
dev_checkbox_toggled_cb (GtkWidget *check, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *combo, *entry, *ok_button;

	combo = GTK_WIDGET (gtk_builder_get_object (builder, "dev_type_combo"));
	entry = GTK_WIDGET (gtk_builder_get_object (builder, "dev_entry"));
	ok_button = GTK_WIDGET (gtk_builder_get_object (builder, "ok_button"));

	/* Set values to default ones */
	if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (check))) {
		gtk_entry_set_text (GTK_ENTRY (entry), "");
		gtk_combo_box_set_active (GTK_COMBO_BOX (combo), DEVICE_TYPE_IDX_TUN);
	}

	checkbox_toggled_update_widget_cb (check, combo);
	checkbox_toggled_update_widget_cb (check, entry);
	device_name_changed_cb (GTK_ENTRY (entry), ok_button);
}

static gboolean
_hash_get_boolean (GHashTable *hash,
                   const char *key)
{
	const char *value;

	nm_assert (hash);
	nm_assert (key && key[0]);

	value = g_hash_table_lookup (hash, key);

	return nm_streq0 (value, "yes");
}

static GtkToggleButton *
_builder_init_toggle_button (GtkBuilder *builder,
                             const char *widget_name,
                             gboolean active_state)
{
	GtkToggleButton *widget;

	widget = (GtkToggleButton *) gtk_builder_get_object (builder, widget_name);
	g_return_val_if_fail (GTK_IS_TOGGLE_BUTTON (widget), NULL);

	gtk_toggle_button_set_active (widget, active_state);
	return widget;
}

static void
_builder_init_optional_spinbutton (GtkBuilder *builder,
                                   const char *checkbutton_name,
                                   const char *spinbutton_name,
                                   gboolean active_state,
                                   gint64 value)
{
	GtkWidget *widget;
	GtkWidget *spin;

	widget = (GtkWidget *) gtk_builder_get_object (builder, checkbutton_name);
	g_return_if_fail (GTK_IS_TOGGLE_BUTTON (widget));

	spin = (GtkWidget *) gtk_builder_get_object (builder, spinbutton_name);
	g_return_if_fail (GTK_IS_SPIN_BUTTON (spin));

	g_signal_connect ((GObject *) widget, "toggled", G_CALLBACK (checkbox_toggled_update_widget_cb), spin);

	gtk_spin_button_set_value ((GtkSpinButton *) spin, (double) value);

	gtk_widget_set_sensitive (spin, active_state);
	gtk_toggle_button_set_active ((GtkToggleButton *) widget, active_state);
}

static void
ping_exit_restart_checkbox_toggled_cb (GtkWidget *check, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *combo, *spin;

	combo = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_combo"));
	spin = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_spinbutton"));

	checkbox_toggled_update_widget_cb (check, combo);
	checkbox_toggled_update_widget_cb (check, spin);
}

#define TA_DIR_COL_NAME 0
#define TA_DIR_COL_NUM 1

GtkWidget *
advanced_dialog_new (GHashTable *hash, const char *contype)
{
	GtkBuilder *builder;
	GtkWidget *dialog = NULL;
	GtkWidget *widget, *combo, *spin, *entry, *ok_button;
	const char *value, *value2;
	const char *dev, *dev_type, *tap_dev;
	GtkListStore *store;
	GtkTreeIter iter;
	guint i;
	guint32 active;
	guint32 pw_flags = NM_SETTING_SECRET_FLAG_NONE;
	GError *error = NULL;

	g_return_val_if_fail (hash != NULL, NULL);

	builder = gtk_builder_new ();

	gtk_builder_set_translation_domain (builder, GETTEXT_PACKAGE);

	if (!gtk_builder_add_from_resource (builder, "/org/freedesktop/network-manager-openvpn/nm-openvpn-dialog.ui", &error)) {
		g_error_free (error);
		g_object_unref (G_OBJECT (builder));
		g_return_val_if_reached (NULL);
	}

	dialog = GTK_WIDGET (gtk_builder_get_object (builder, "openvpn-advanced-dialog"));
	if (!dialog) {
		g_object_unref (G_OBJECT (builder));
		g_return_val_if_reached (NULL);
	}
	gtk_window_set_modal (GTK_WINDOW (dialog), TRUE);

	g_object_set_data_full (G_OBJECT (dialog), "builder",
	                        builder, (GDestroyNotify) g_object_unref);
	g_object_set_data (G_OBJECT (dialog), "connection-type", GINT_TO_POINTER (contype));

	ok_button = GTK_WIDGET (gtk_builder_get_object (builder, "ok_button"));


	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_RENEG_SECONDS);
	_builder_init_optional_spinbutton (builder, "reneg_checkbutton", "reneg_spinbutton", !!value,
	                                   _nm_utils_ascii_str_to_int64 (value, 10, 0, G_MAXINT, 0));


	/* Proxy support */
	combo = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_type_combo"));

	store = gtk_list_store_new (1, G_TYPE_STRING);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Not required"), -1);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("HTTP"), -1);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("SOCKS"), -1);

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PROXY_SERVER);
	value2 = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PROXY_PORT);
	if (value && strlen (value) && value2 && strlen (value2)) {
		long int tmp = 0;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_server_entry"));
		gtk_entry_set_text (GTK_ENTRY (widget), value);

		errno = 0;
		tmp = strtol (value2, NULL, 10);
		if (errno != 0 || tmp < 0 || tmp > 65535)
			tmp = 0;
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_port_spinbutton"));
		gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), (gdouble) tmp);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_retry_checkbutton"));
		value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PROXY_RETRY);
		if (value && !strcmp (value, "yes"))
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);

		value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_HTTP_PROXY_USERNAME);
		if (value && strlen (value)) {
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_username_entry"));
			gtk_entry_set_text (GTK_ENTRY (widget), value);
		}

		value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD);
		if (value && strlen (value)) {
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_password_entry"));
			gtk_entry_set_text (GTK_ENTRY (widget), value);
		}

		value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD"-flags");
		if (value && strlen (value)) {
			errno = 0;
			tmp = strtol (value, NULL, 10);
			if (errno != 0 || tmp < 0 || tmp > 65535)
				tmp = 0;
			pw_flags = (guint32) tmp;
		}
	}
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_password_entry"));
	nma_utils_setup_password_storage (widget, pw_flags, NULL, NULL,
	                                  TRUE, FALSE);

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PROXY_TYPE);
	active = PROXY_TYPE_NONE;
	if (value) {
		if (!strcmp (value, "http"))
			active = PROXY_TYPE_HTTP;
		else if (!strcmp (value, "socks"))
			active = PROXY_TYPE_SOCKS;
	}

	gtk_combo_box_set_model (GTK_COMBO_BOX (combo), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (combo), active);
	proxy_type_changed (GTK_COMBO_BOX (combo), builder);
	g_signal_connect (G_OBJECT (combo), "changed", G_CALLBACK (proxy_type_changed), builder);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "show_proxy_password"));
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (show_proxy_password_toggled_cb), builder);


	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PORT);
	_builder_init_optional_spinbutton (builder, "port_checkbutton", "port_spinbutton", !!value,
	                                   _nm_utils_ascii_str_to_int64 (value, 10, 1, 65535, 1194));


	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_TUNNEL_MTU);
	_builder_init_optional_spinbutton (builder, "tunmtu_checkbutton", "tunmtu_spinbutton", !!value,
	                                   _nm_utils_ascii_str_to_int64 (value, 10, 1, 65535, 1500));


	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_FRAGMENT_SIZE);
	_builder_init_optional_spinbutton (builder, "fragment_checkbutton", "fragment_spinbutton", !!value,
	                                   _nm_utils_ascii_str_to_int64 (value, 10, 0, 65535, 1300));


	value = comp_lzo_values_conf_coerce (g_hash_table_lookup (hash, NM_OPENVPN_KEY_COMP_LZO));
	widget = GTK_WIDGET (_builder_init_toggle_button (builder, "lzo_checkbutton", value != NULL));
	combo = GTK_WIDGET (gtk_builder_get_object (builder, "lzo_combo"));
	store = gtk_list_store_new (1, G_TYPE_STRING);
	active = 0;
	for (i = 0; i < G_N_ELEMENTS (comp_lzo_values); i++) {
		gtk_list_store_append (store, &iter);
		gtk_list_store_set (store, &iter,
		                    0, comp_lzo_values_conf_to_display (comp_lzo_values[i]),
		                    -1);
		if (nm_streq (comp_lzo_values[i], value ?: "adaptive"))
			active = i;
	}
	gtk_combo_box_set_model (GTK_COMBO_BOX (combo), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (combo), active);
	g_object_bind_property (widget, "active", combo, "sensitive", G_BINDING_SYNC_CREATE);

	_builder_init_toggle_button (builder, "mssfix_checkbutton", _hash_get_boolean (hash, NM_OPENVPN_KEY_MSSFIX));
	_builder_init_toggle_button (builder, "float_checkbutton", _hash_get_boolean (hash, NM_OPENVPN_KEY_FLOAT));
	_builder_init_toggle_button (builder, "tcp_checkbutton", _hash_get_boolean (hash, NM_OPENVPN_KEY_PROTO_TCP));


	/* Populate device-related widgets */
	dev =      g_hash_table_lookup (hash, NM_OPENVPN_KEY_DEV);
	dev_type = g_hash_table_lookup (hash, NM_OPENVPN_KEY_DEV_TYPE);
	tap_dev =  g_hash_table_lookup (hash, NM_OPENVPN_KEY_TAP_DEV);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "dev_checkbutton"));
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), (dev && *dev) || dev_type || tap_dev);
	dev_checkbox_toggled_cb (widget, builder);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (dev_checkbox_toggled_cb), builder);
	combo = GTK_WIDGET (gtk_builder_get_object (builder, "dev_type_combo"));
	active = DEVICE_TYPE_IDX_TUN;
	if (   !g_strcmp0 (dev_type, "tap")
	    || (!dev_type && dev && g_str_has_prefix (dev, "tap"))
	    || (!dev_type && !g_strcmp0 (tap_dev, "yes")))
		active = DEVICE_TYPE_IDX_TAP;

	store = gtk_list_store_new (1, G_TYPE_STRING);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("TUN"), -1);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("TAP"), -1);
	gtk_combo_box_set_model (GTK_COMBO_BOX (combo), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (combo), active);

	entry = GTK_WIDGET (gtk_builder_get_object (builder, "dev_entry"));
	gtk_entry_set_max_length (GTK_ENTRY (entry), 15);  /* interface name is max 15 chars */
	gtk_entry_set_placeholder_text (GTK_ENTRY (entry), _("(automatic)"));
	g_signal_connect (G_OBJECT (entry), "insert-text", G_CALLBACK (device_name_filter_cb), NULL);
	g_signal_connect (G_OBJECT (entry), "changed", G_CALLBACK (device_name_changed_cb), ok_button);
	gtk_entry_set_text (GTK_ENTRY (entry), dev ?: "");


	_builder_init_toggle_button (builder, "remote_random_checkbutton", _hash_get_boolean (hash, NM_OPENVPN_KEY_REMOTE_RANDOM));
	_builder_init_toggle_button (builder, "tun_ipv6_checkbutton", _hash_get_boolean (hash, NM_OPENVPN_KEY_TUN_IPV6));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "cipher_combo"));
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_CIPHER);
	populate_cipher_combo (GTK_COMBO_BOX (widget), value);


	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_KEYSIZE);
	_builder_init_optional_spinbutton (builder, "keysize_checkbutton", "keysize_spinbutton", !!value,
	                                   _nm_utils_ascii_str_to_int64 (value, 10, 1, 65535, 128));


	widget = GTK_WIDGET (gtk_builder_get_object (builder, "hmacauth_combo"));
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_AUTH);
	populate_hmacauth_combo (GTK_COMBO_BOX (widget), value);

	entry = GTK_WIDGET (gtk_builder_get_object (builder, "tls_remote_entry"));
	combo = GTK_WIDGET (gtk_builder_get_object (builder, "tls_remote_mode_combo"));
	populate_tls_remote_mode_entry_combo (GTK_ENTRY (entry), GTK_COMBO_BOX (combo),
	                                      g_hash_table_lookup (hash, NM_OPENVPN_KEY_TLS_REMOTE),
	                                      g_hash_table_lookup (hash, NM_OPENVPN_KEY_VERIFY_X509_NAME));
	g_signal_connect (G_OBJECT (entry), "changed", G_CALLBACK (tls_remote_changed), builder);
	g_signal_connect (G_OBJECT (combo), "changed", G_CALLBACK (tls_remote_changed), builder);
	tls_remote_changed (entry, builder);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_cert_tls_checkbutton"));
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_REMOTE_CERT_TLS);
	if (value && strlen (value))
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (remote_tls_cert_toggled_cb), builder);
	remote_tls_cert_toggled_cb (widget, builder);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_cert_tls_combo"));
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_REMOTE_CERT_TLS);
	populate_remote_cert_tls_combo (GTK_COMBO_BOX (widget), value);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ns_cert_type_checkbutton"));
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_NS_CERT_TYPE);
	if (value && strlen (value))
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (ns_cert_type_toggled_cb), builder);
	ns_cert_type_toggled_cb (widget, builder);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ns_cert_type_combo"));
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_NS_CERT_TYPE);
	populate_ns_cert_type_combo (GTK_COMBO_BOX (widget), value);

	if (NM_IN_STRSET (contype,
	                  NM_OPENVPN_CONTYPE_TLS,
	                  NM_OPENVPN_CONTYPE_PASSWORD_TLS,
	                  NM_OPENVPN_CONTYPE_PASSWORD)) {
		int direction = -1;

		/* Initialize direction combo */
		combo = GTK_WIDGET (gtk_builder_get_object (builder, "direction_combo"));
		store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_INT);
		gtk_list_store_append (store, &iter);
		gtk_list_store_set (store, &iter, TA_DIR_COL_NAME, _("None"), TA_DIR_COL_NUM, -1, -1);
		gtk_list_store_append (store, &iter);
		gtk_list_store_set (store, &iter, TA_DIR_COL_NAME, "0", TA_DIR_COL_NUM, 0, -1);
		gtk_list_store_append (store, &iter);
		gtk_list_store_set (store, &iter, TA_DIR_COL_NAME, "1", TA_DIR_COL_NUM, 1, -1);
		gtk_combo_box_set_model (GTK_COMBO_BOX (combo), GTK_TREE_MODEL (store));
		g_object_unref (store);
		gtk_combo_box_set_active (GTK_COMBO_BOX (combo), 0);

		combo = GTK_WIDGET (gtk_builder_get_object (builder, "tls_auth_mode"));
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_auth_chooser"));
		value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_TA);
		value2 = g_hash_table_lookup (hash, NM_OPENVPN_KEY_TLS_CRYPT);
		if (value2 && value2[0]) {
			gtk_combo_box_set_active (GTK_COMBO_BOX (combo), TLS_AUTH_MODE_CRYPT);
			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), value2);
		} else if (value && value[0]) {
			gtk_combo_box_set_active (GTK_COMBO_BOX (combo), TLS_AUTH_MODE_AUTH);
			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), value);
			value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_TA_DIR);
			if (value && value[0]) {
				direction = (int) strtol (value, NULL, 10);
				/* If direction is not 0 or 1, use no direction */
				if (direction != 0 && direction != 1)
					direction = -1;
			}
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "direction_combo"));
			gtk_combo_box_set_active (GTK_COMBO_BOX (widget), direction + 1);
		} else
			gtk_combo_box_set_active (GTK_COMBO_BOX (combo), TLS_AUTH_MODE_NONE);

		g_signal_connect (G_OBJECT (combo), "changed", G_CALLBACK (tls_auth_toggled_cb), builder);
		tls_auth_toggled_cb (combo, builder);
	} else {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "options_notebook"));
		gtk_notebook_remove_page (GTK_NOTEBOOK (widget), 2);
	}


	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PING);
	_builder_init_optional_spinbutton (builder, "ping_checkbutton", "ping_spinbutton", !!value,
	                                   _nm_utils_ascii_str_to_int64 (value, 10, 1, 65535, 30));


	/* ping-exit / ping-restart */
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_checkbutton"));
	spin = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_spinbutton"));
	combo = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_combo"));
	g_signal_connect ((GObject *) widget, "toggled", G_CALLBACK (ping_exit_restart_checkbox_toggled_cb), builder);

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PING_EXIT);
	active = PING_EXIT;
	if (!value) {
		value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PING_RESTART);
		if (value)
			active = PING_RESTART;
	}

	store = gtk_list_store_new (1, G_TYPE_STRING);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("ping-exit"), -1);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("ping-restart"), -1);
	gtk_combo_box_set_model (GTK_COMBO_BOX (combo), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active ((GtkComboBox *) combo, active);

	gtk_spin_button_set_value ((GtkSpinButton *) spin,
	                           (double) _nm_utils_ascii_str_to_int64 (value, 10, 1, 65535, 30));
	gtk_widget_set_sensitive (combo, !!value);
	gtk_widget_set_sensitive (spin, !!value);
	gtk_toggle_button_set_active ((GtkToggleButton *) widget, !!value);

	/* MTU discovery */
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "mtu_disc_checkbutton"));
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_MTU_DISC);
	if (value && value[0]) {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
		combo = GTK_WIDGET (gtk_builder_get_object (builder, "mtu_disc_combo"));
		if (nm_streq (value, "maybe"))
			gtk_combo_box_set_active (GTK_COMBO_BOX (combo), 1);
		else if (nm_streq (value, "yes"))
			gtk_combo_box_set_active (GTK_COMBO_BOX (combo), 2);
		else
			gtk_combo_box_set_active (GTK_COMBO_BOX (combo), 0);
	}
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (mtu_disc_toggled_cb), builder);
	mtu_disc_toggled_cb (widget, builder);

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_MAX_ROUTES);
	_builder_init_optional_spinbutton (builder, "max_routes_checkbutton", "max_routes_spinbutton", !!value,
	                                   _nm_utils_ascii_str_to_int64 (value, 10, 0, 100000000, 100));

	return dialog;
}

GHashTable *
advanced_dialog_new_hash_from_dialog (GtkWidget *dialog, GError **error)
{
	GHashTable *hash;
	GtkWidget *widget, *entry, *combo;
	GtkBuilder *builder;
	const char *contype = NULL;
	const char *value;
	int active;
	int proxy_type = PROXY_TYPE_NONE;
	GtkTreeModel *model;
	GtkTreeIter iter;

	g_return_val_if_fail (dialog != NULL, NULL);
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	builder = g_object_get_data (G_OBJECT (dialog), "builder");
	g_return_val_if_fail (builder != NULL, NULL);

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "reneg_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		int reneg_seconds;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "reneg_spinbutton"));
		reneg_seconds = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_RENEG_SECONDS), g_strdup_printf ("%d", reneg_seconds));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tunmtu_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		int tunmtu_size;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "tunmtu_spinbutton"));
		tunmtu_size = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_TUNNEL_MTU), g_strdup_printf ("%d", tunmtu_size));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "fragment_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		int fragment_size;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "fragment_spinbutton"));
		fragment_size = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_FRAGMENT_SIZE), g_strdup_printf ("%d", fragment_size));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "port_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		int port;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "port_spinbutton"));
		port = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_PORT), g_strdup_printf ("%d", port));
	}

	/* Proxy support */
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_type_combo"));
	proxy_type = gtk_combo_box_get_active (GTK_COMBO_BOX (widget));
	if (proxy_type != PROXY_TYPE_NONE) {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_server_entry"));
		value = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
		if (value && strlen (value)) {
			int proxy_port;

			if (proxy_type == PROXY_TYPE_HTTP)
				g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_PROXY_TYPE), g_strdup ("http"));
			else if (proxy_type == PROXY_TYPE_SOCKS)
				g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_PROXY_TYPE), g_strdup ("socks"));

			g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_PROXY_SERVER), g_strdup (value));

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_port_spinbutton"));
			proxy_port = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
			if (proxy_port > 0) {
				g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_PROXY_PORT),
				                     g_strdup_printf ("%d", proxy_port));
			}

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_retry_checkbutton"));
			if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
				g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_PROXY_RETRY), g_strdup ("yes"));

			if (proxy_type == PROXY_TYPE_HTTP) {
				guint32 pw_flags;

				widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_username_entry"));
				value = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
				if (value && strlen (value)) {
					g_hash_table_insert (hash,
					                     g_strdup (NM_OPENVPN_KEY_HTTP_PROXY_USERNAME),
					                     g_strdup (value));
				}

				widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_password_entry"));
				value = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
				if (value && strlen (value)) {
					g_hash_table_insert (hash,
					                     g_strdup (NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD),
					                     g_strdup (value));
				}

				pw_flags = nma_utils_menu_to_secret_flags (widget);
				if (pw_flags != NM_SETTING_SECRET_FLAG_NONE) {
					g_hash_table_insert (hash,
					                     g_strdup (NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD"-flags"),
					                     g_strdup_printf ("%d", pw_flags));
				}
			}
		}
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "lzo_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		combo = GTK_WIDGET (gtk_builder_get_object (builder, "lzo_combo"));
		active = gtk_combo_box_get_active (GTK_COMBO_BOX (combo));
		if (active >= 0 && active < G_N_ELEMENTS (comp_lzo_values))
			g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_COMP_LZO), g_strdup (comp_lzo_values[active]));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "mssfix_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_MSSFIX), g_strdup ("yes"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "float_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_FLOAT), g_strdup ("yes"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tcp_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_PROTO_TCP), g_strdup ("yes"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "dev_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		int device_type;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "dev_type_combo"));
		device_type = gtk_combo_box_get_active (GTK_COMBO_BOX (widget));
		g_hash_table_insert (hash,
		                     g_strdup (NM_OPENVPN_KEY_DEV_TYPE),
		                     g_strdup (device_type == DEVICE_TYPE_IDX_TUN ? "tun" : "tap"));

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "dev_entry"));
		value = gtk_entry_get_text (GTK_ENTRY (widget));
		if (value && value[0] != '\0')
			g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_DEV), g_strdup (value));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_random_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_REMOTE_RANDOM), g_strdup ("yes"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tun_ipv6_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_TUN_IPV6), g_strdup ("yes"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "cipher_combo"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
		char *cipher = NULL;
		gboolean is_default = TRUE;

		gtk_tree_model_get (model, &iter,
		                    TLS_CIPHER_COL_NAME, &cipher,
		                    TLS_CIPHER_COL_DEFAULT, &is_default, -1);
		if (!is_default && cipher) {
			g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_CIPHER), g_strdup (cipher));
		}
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "keysize_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		int keysize_val;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "keysize_spinbutton"));
		keysize_val = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_KEYSIZE), g_strdup_printf ("%d", keysize_val));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "hmacauth_combo"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
		char *hmacauth = NULL;
		gboolean is_default = TRUE;

		gtk_tree_model_get (model, &iter,
		                    HMACAUTH_COL_VALUE, &hmacauth,
		                    HMACAUTH_COL_DEFAULT, &is_default, -1);
		if (!is_default && hmacauth) {
			g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_AUTH), g_strdup (hmacauth));
		}
	}

	contype = g_object_get_data (G_OBJECT (dialog), "connection-type");
	if (   !strcmp (contype, NM_OPENVPN_CONTYPE_TLS)
	    || !strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD_TLS)
	    || !strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD)) {
		char *filename;

		entry = GTK_WIDGET (gtk_builder_get_object (builder, "tls_remote_entry"));
		value = gtk_entry_get_text (GTK_ENTRY (entry));

		combo = GTK_WIDGET (gtk_builder_get_object (builder, "tls_remote_mode_combo"));
		model = gtk_combo_box_get_model (GTK_COMBO_BOX (combo));

		if (value && strlen (value) && gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter)) {
			gs_free char *tls_remote_mode = NULL;
			gtk_tree_model_get (model, &iter, TLS_REMOTE_MODE_COL_VALUE, &tls_remote_mode, -1);

			if (!g_strcmp0 (tls_remote_mode, TLS_REMOTE_MODE_NONE)) {
				// pass
			} else if (!g_strcmp0 (tls_remote_mode, TLS_REMOTE_MODE_LEGACY)) {
				g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_TLS_REMOTE), g_strdup(value));
			} else {
				char *x509_name = g_strdup_printf ("%s:%s", tls_remote_mode, value);
				g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_VERIFY_X509_NAME), x509_name);
			}
		}

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_cert_tls_checkbutton"));
		if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_cert_tls_combo"));
			model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
			if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
				char *remote_cert = NULL;

				gtk_tree_model_get (model, &iter, REMOTE_CERT_COL_VALUE, &remote_cert, -1);
				if (remote_cert)
					g_hash_table_insert (hash,
					                     g_strdup (NM_OPENVPN_KEY_REMOTE_CERT_TLS),
					                     remote_cert);
			}
		}

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ns_cert_type_checkbutton"));
		if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "ns_cert_type_combo"));
			model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
			if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
				char *type = NULL;

				gtk_tree_model_get (model, &iter, NS_CERT_TYPE_COL_VALUE, &type, -1);
				if (type)
					g_hash_table_insert (hash,
					                     g_strdup (NM_OPENVPN_KEY_NS_CERT_TYPE),
					                     type);
			}
		}

		combo = GTK_WIDGET (gtk_builder_get_object (builder, "tls_auth_mode"));
		switch (gtk_combo_box_get_active (GTK_COMBO_BOX (combo))) {
		case TLS_AUTH_MODE_AUTH:
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_auth_chooser"));
			filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
			if (filename && filename[0])
				g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_TA), g_strdup (filename));
			g_free (filename);

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "direction_combo"));
			model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
			if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
				int direction = -1;

				gtk_tree_model_get (model, &iter, TA_DIR_COL_NUM, &direction, -1);
				if (direction >= 0) {
					g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_TA_DIR),
					                     g_strdup_printf ("%d", direction));
				}
			}
			break;
		case TLS_AUTH_MODE_CRYPT:
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_auth_chooser"));
			filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
			if (filename && filename[0])
				g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_TLS_CRYPT), g_strdup (filename));
			g_free (filename);
			break;
		case TLS_AUTH_MODE_NONE:
			break;
		}
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ping_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		int ping_val;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ping_spinbutton"));
		ping_val = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));

		g_hash_table_insert (hash,
		                     g_strdup (NM_OPENVPN_KEY_PING),
		                     g_strdup_printf ("%d", ping_val));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		int ping_exit_type, ping_val;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_combo"));
		ping_exit_type = gtk_combo_box_get_active (GTK_COMBO_BOX (widget));

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_spinbutton"));
		ping_val = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));

		g_hash_table_insert (hash,
		                     ping_exit_type == PING_EXIT ?
		                       g_strdup (NM_OPENVPN_KEY_PING_EXIT) :
		                       g_strdup (NM_OPENVPN_KEY_PING_RESTART),
		                     g_strdup_printf ("%d", ping_val));
	}

	/* max routes */
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "max_routes_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		int max_routes;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "max_routes_spinbutton"));
		max_routes = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_MAX_ROUTES), g_strdup_printf ("%d", max_routes));
	}

	/* MTU discovery */
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "mtu_disc_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		char *val = NULL;

		combo = GTK_WIDGET (gtk_builder_get_object (builder, "mtu_disc_combo"));
		switch (gtk_combo_box_get_active (GTK_COMBO_BOX (combo))) {
		case 0:
			val = "no";
			break;
		case 1:
			val = "maybe";
			break;
		case 2:
			val = "yes";
			break;
		}
		if (val) {
			g_hash_table_insert (hash,
			                     g_strdup (NM_OPENVPN_KEY_MTU_DISC),
			                     g_strdup (val));
		}
	}

	return hash;
}

