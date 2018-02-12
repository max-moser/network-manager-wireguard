/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
 *
 * Dan Williams <dcbw@redhat.com>
 * Tim Niemueller <tim@niemueller.de>
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
 * (C) Copyright 2004 - 2008 Red Hat, Inc.
 *               2005 Tim Niemueller [www.niemueller.de]
 */

#include "nm-default.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <gtk/gtk.h>

#include <libsecret/secret.h>

#include <nma-vpn-password-dialog.h>

#include "utils.h"

#define KEYRING_UUID_TAG "connection-uuid"
#define KEYRING_SN_TAG "setting-name"
#define KEYRING_SK_TAG "setting-key"

static const SecretSchema network_manager_secret_schema = {
	"org.freedesktop.NetworkManager.Connection",
	SECRET_SCHEMA_DONT_MATCH_NAME,
	{
		{ KEYRING_UUID_TAG, SECRET_SCHEMA_ATTRIBUTE_STRING },
		{ KEYRING_SN_TAG, SECRET_SCHEMA_ATTRIBUTE_STRING },
		{ KEYRING_SK_TAG, SECRET_SCHEMA_ATTRIBUTE_STRING },
		{ NULL, 0 },
	}
};

#define UI_KEYFILE_GROUP "VPN Plugin UI"

static char *
keyring_lookup_secret (const char *uuid, const char *secret_name)
{
	GHashTable *attrs;
	GList *list;
	char *secret = NULL;

	attrs = secret_attributes_build (&network_manager_secret_schema,
	                                 KEYRING_UUID_TAG, uuid,
	                                 KEYRING_SN_TAG, NM_SETTING_VPN_SETTING_NAME,
	                                 KEYRING_SK_TAG, secret_name,
	                                 NULL);

	list = secret_service_search_sync (NULL, &network_manager_secret_schema, attrs,
	                                   SECRET_SEARCH_ALL | SECRET_SEARCH_UNLOCK | SECRET_SEARCH_LOAD_SECRETS,
	                                   NULL, NULL);
	if (list && list->data) {
		SecretItem *item = list->data;
		SecretValue *value = secret_item_get_secret (item);

		if (value) {
			secret = g_strdup (secret_value_get (value, NULL));
			secret_value_unref (value);
		}
	}

	g_list_free_full (list, g_object_unref);
	g_hash_table_unref (attrs);
	return secret;
}

/*****************************************************************/

typedef void (*NoSecretsRequiredFunc) (void);

/* Returns TRUE on success, FALSE on cancel */
typedef gboolean (*AskUserFunc) (const char *vpn_name,
                                 const char *prompt,
                                 gboolean need_password,
                                 const char *existing_password,
                                 char **out_new_password,
                                 gboolean need_certpass,
                                 const char *existing_certpass,
                                 char **out_new_certpass,
                                 gboolean need_proxypass,
                                 const char *existing_proxypass,
                                 char **out_new_proxypass);

typedef void (*FinishFunc) (const char *vpn_name,
                            const char *prompt,
                            gboolean allow_interaction,
                            gboolean need_password,
                            const char *password,
                            gboolean need_certpass,
                            const char *certpass,
                            gboolean need_proxypass,
                            const char *proxypass);

/*****************************************************************/
/* External UI mode stuff */

static void
keyfile_add_entry_info (GKeyFile    *keyfile,
                        const gchar *key,
                        const gchar *value,
                        const gchar *label,
                        gboolean     is_secret,
                        gboolean     should_ask)
{
	g_key_file_set_string (keyfile, key, "Value", value);
	g_key_file_set_string (keyfile, key, "Label", label);
	g_key_file_set_boolean (keyfile, key, "IsSecret", is_secret);
	g_key_file_set_boolean (keyfile, key, "ShouldAsk", should_ask);
}

static void
keyfile_print_stdout (GKeyFile *keyfile)
{
	gchar *data;
	gsize length;

	data = g_key_file_to_data (keyfile, &length, NULL);

	fputs (data, stdout);

	g_free (data);
}

static void
eui_no_secrets_required (void)
{
	GKeyFile *keyfile;

	keyfile = g_key_file_new ();

	g_key_file_set_integer (keyfile, UI_KEYFILE_GROUP, "Version", 2);
	keyfile_add_entry_info (keyfile, NM_OPENVPN_KEY_NOSECRET, "true", "", TRUE, FALSE);
	keyfile_print_stdout (keyfile);
	g_key_file_unref (keyfile);
}

static void
eui_finish (const char *vpn_name,
            const char *prompt,
            gboolean allow_interaction,
            gboolean need_password,
            const char *existing_password,
            gboolean need_certpass,
            const char *existing_certpass,
            gboolean need_proxypass,
            const char *existing_proxypass)
{
	GKeyFile *keyfile;
	char *title;

	keyfile = g_key_file_new ();

	g_key_file_set_integer (keyfile, UI_KEYFILE_GROUP, "Version", 2);
	g_key_file_set_string (keyfile, UI_KEYFILE_GROUP, "Description", prompt);

	title = g_strdup_printf (_("Authenticate VPN %s"), vpn_name);
	g_key_file_set_string (keyfile, UI_KEYFILE_GROUP, "Title", title);
	g_free (title);

	keyfile_add_entry_info (keyfile,
	                        NM_OPENVPN_KEY_PASSWORD,
	                        existing_password ? existing_password : "",
	                        _("Password:"),
	                        TRUE,
	                        need_password && allow_interaction);

	keyfile_add_entry_info (keyfile,
	                        NM_OPENVPN_KEY_CERTPASS,
	                        existing_certpass ? existing_certpass : "",
	                        _("Certificate password:"),
	                        TRUE,
	                        need_certpass && allow_interaction);

	keyfile_add_entry_info (keyfile,
	                        NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD,
	                        existing_proxypass ? existing_proxypass : "",
	                        _("HTTP proxy password:"),
	                        TRUE,
	                        need_proxypass && allow_interaction);

	keyfile_print_stdout (keyfile);
	g_key_file_unref (keyfile);
}

/*****************************************************************/

static void
std_no_secrets_required (void)
{
	printf ("%s\n%s\n\n\n", NM_OPENVPN_KEY_NOSECRET, "true");
}

static gboolean
std_ask_user (const char *vpn_name,
              const char *prompt,
              gboolean need_password,
              const char *existing_password,
              char **out_new_password,
              gboolean need_certpass,
              const char *existing_certpass,
              char **out_new_certpass,
              gboolean need_proxypass,
              const char *existing_proxypass,
              char **out_new_proxypass)
{
	NMAVpnPasswordDialog *dialog;
	gboolean success = FALSE;

	g_return_val_if_fail (vpn_name != NULL, FALSE);
	g_return_val_if_fail (prompt != NULL, FALSE);
	g_return_val_if_fail (out_new_password != NULL, FALSE);
	g_return_val_if_fail (out_new_certpass != NULL, FALSE);
	g_return_val_if_fail (out_new_proxypass != NULL, FALSE);

	dialog = NMA_VPN_PASSWORD_DIALOG (nma_vpn_password_dialog_new (_("Authenticate VPN"), prompt, NULL));

	/* pre-fill dialog with existing passwords */
	nma_vpn_password_dialog_set_show_password (dialog, need_password);
	if (need_password)
		nma_vpn_password_dialog_set_password (dialog, existing_password);

	nma_vpn_password_dialog_set_show_password_secondary (dialog, need_certpass);
	if (need_certpass) {
		nma_vpn_password_dialog_set_password_secondary_label (dialog, _("Certificate pass_word:") );
		nma_vpn_password_dialog_set_password_secondary (dialog, existing_certpass);
	}

	nma_vpn_password_dialog_set_show_password_ternary (dialog, need_proxypass);
	if (need_proxypass) {
		nma_vpn_password_dialog_set_password_ternary_label (dialog, _("_HTTP proxy password:"));
		nma_vpn_password_dialog_set_password_ternary (dialog, existing_proxypass);
	}

	gtk_widget_show (GTK_WIDGET (dialog));
	if (nma_vpn_password_dialog_run_and_block (dialog)) {
		if (need_password)
			*out_new_password = g_strdup (nma_vpn_password_dialog_get_password (dialog));
		if (need_certpass)
			*out_new_certpass = g_strdup (nma_vpn_password_dialog_get_password_secondary (dialog));
		if (need_proxypass)
			*out_new_proxypass = g_strdup (nma_vpn_password_dialog_get_password_ternary (dialog));

		success = TRUE;
	}

	gtk_widget_destroy (GTK_WIDGET (dialog));
	return success;
}

static void
wait_for_quit (void)
{
	GString *str;
	char c;
	ssize_t n;
	time_t start;

	str = g_string_sized_new (10);
	start = time (NULL);
	do {
		errno = 0;
		n = read (0, &c, 1);
		if (n == 0 || (n < 0 && errno == EAGAIN))
			g_usleep (G_USEC_PER_SEC / 10);
		else if (n == 1) {
			g_string_append_c (str, c);
			if (strstr (str->str, "QUIT") || (str->len > 10))
				break;
		} else
			break;
	} while (time (NULL) < start + 20);
	g_string_free (str, TRUE);
}

static void
std_finish (const char *vpn_name,
            const char *prompt,
            gboolean allow_interaction,
            gboolean need_password,
            const char *password,
            gboolean need_certpass,
            const char *certpass,
            gboolean need_proxypass,
            const char *proxypass)
{
	/* Send the passwords back to our parent */
	if (password)
		printf ("%s\n%s\n", NM_OPENVPN_KEY_PASSWORD, password);
	if (certpass)
		printf ("%s\n%s\n", NM_OPENVPN_KEY_CERTPASS, certpass);
	if (proxypass)
		printf ("%s\n%s\n", NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD, proxypass);
	printf ("\n\n");

	/* for good measure, flush stdout since Kansas is going Bye-Bye */
	fflush (stdout);

	/* Wait for quit signal */
	wait_for_quit ();
}

/*****************************************************************/

static void
get_existing_passwords (GHashTable *vpn_data,
                        GHashTable *existing_secrets,
                        const char *vpn_uuid,
                        gboolean need_password,
                        gboolean need_certpass,
                        gboolean need_proxypass,
                        char **out_password,
                        char **out_certpass,
                        char **out_proxypass)
{
	NMSettingSecretFlags pw_flags = NM_SETTING_SECRET_FLAG_NONE;
	NMSettingSecretFlags cp_flags = NM_SETTING_SECRET_FLAG_NONE;
	NMSettingSecretFlags proxy_flags = NM_SETTING_SECRET_FLAG_NONE;

	g_return_if_fail (out_password != NULL);
	g_return_if_fail (out_certpass != NULL);
	g_return_if_fail (out_proxypass != NULL);

	nm_vpn_service_plugin_get_secret_flags (vpn_data, NM_OPENVPN_KEY_PASSWORD, &pw_flags);
	if (need_password) {
		if (!(pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)) {
			*out_password = g_strdup (g_hash_table_lookup (existing_secrets, NM_OPENVPN_KEY_PASSWORD));
			if (!*out_password)
				*out_password = keyring_lookup_secret (vpn_uuid, NM_OPENVPN_KEY_PASSWORD);
		}
	}

	nm_vpn_service_plugin_get_secret_flags (vpn_data, NM_OPENVPN_KEY_CERTPASS, &cp_flags);
	if (need_certpass) {
		if (!(cp_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)) {
			*out_certpass = g_strdup (g_hash_table_lookup (existing_secrets, NM_OPENVPN_KEY_CERTPASS));
			if (!*out_certpass)
				*out_certpass = keyring_lookup_secret (vpn_uuid, NM_OPENVPN_KEY_CERTPASS);
		}
	}

	nm_vpn_service_plugin_get_secret_flags (vpn_data, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD, &proxy_flags);
	if (need_proxypass) {
		if (!(proxy_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)) {
			*out_proxypass = g_strdup (g_hash_table_lookup (existing_secrets, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD));
			if (!*out_proxypass)
				*out_proxypass = keyring_lookup_secret (vpn_uuid, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD);
		}
	}
}

#define VPN_MSG_TAG "x-vpn-message:"

static char *
get_passwords_required (GHashTable *data,
                        char **hints,
                        gboolean *out_need_password,
                        gboolean *out_need_certpass,
                        gboolean *out_need_proxypass)
{
	const char *ctype, *val;
	NMSettingSecretFlags flags;
	char *prompt = NULL;
	char **iter;

	/* If hints are given, then always ask for what the hints require */
	if (hints && g_strv_length (hints)) {
		for (iter = hints; iter && *iter; iter++) {
			if (!prompt && g_str_has_prefix (*iter, VPN_MSG_TAG))
				prompt = g_strdup (*iter + strlen (VPN_MSG_TAG));
			else if (strcmp (*iter, NM_OPENVPN_KEY_PASSWORD) == 0)
				*out_need_password = TRUE;
			else if (strcmp (*iter, NM_OPENVPN_KEY_CERTPASS) == 0)
				*out_need_certpass = TRUE;
			else if (strcmp (*iter, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD) == 0)
				*out_need_proxypass = TRUE;
		}
		return prompt;
	}

	ctype = g_hash_table_lookup (data, NM_OPENVPN_KEY_CONNECTION_TYPE);
	g_return_val_if_fail (ctype != NULL, NULL);

	if (!strcmp (ctype, NM_OPENVPN_CONTYPE_TLS) || !strcmp (ctype, NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
		/* Normal user password */
		flags = NM_SETTING_SECRET_FLAG_NONE;
		nm_vpn_service_plugin_get_secret_flags (data, NM_OPENVPN_KEY_PASSWORD, &flags);
		if (   !strcmp (ctype, NM_OPENVPN_CONTYPE_PASSWORD_TLS)
		    && !(flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
			*out_need_password = TRUE;

		/* Encrypted private key password */
		val = g_hash_table_lookup (data, NM_OPENVPN_KEY_KEY);
		if (val)
			*out_need_certpass = is_encrypted (val);
	} else if (!strcmp (ctype, NM_OPENVPN_CONTYPE_PASSWORD)) {
		flags = NM_SETTING_SECRET_FLAG_NONE;
		nm_vpn_service_plugin_get_secret_flags (data, NM_OPENVPN_KEY_PASSWORD, &flags);
		if (!(flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
			*out_need_password = TRUE;
	}

	val = g_hash_table_lookup (data, NM_OPENVPN_KEY_PROXY_SERVER);
	if (val && val[0]) {
		flags = NM_SETTING_SECRET_FLAG_NONE;
		nm_vpn_service_plugin_get_secret_flags (data, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD, &flags);
		if (!(flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
			*out_need_proxypass = TRUE;
	}

	return NULL;
}

static void
free_secret (char *p)
{
	if (p) {
		memset (p, 0, strlen (p));
		g_free (p);
	}
}

int 
main (int argc, char *argv[])
{
	gboolean retry = FALSE, allow_interaction = FALSE;
	gchar *vpn_name = NULL;
	gchar *vpn_uuid = NULL;
	gchar *vpn_service = NULL;
	GHashTable *data = NULL, *secrets = NULL;
	gboolean need_password = FALSE, need_certpass = FALSE, need_proxypass = FALSE;
	char *existing_password = NULL, *existing_certpass = NULL, *existing_proxypass = NULL;
	char *new_password = NULL, *new_certpass = NULL, *new_proxypass = NULL;
	char **hints = NULL;
	char *prompt = NULL;
	gboolean external_ui_mode = FALSE, canceled = FALSE, ask_user = FALSE;

	NoSecretsRequiredFunc no_secrets_required_func = NULL;
	AskUserFunc ask_user_func = NULL;
	FinishFunc finish_func = NULL;

	// this describes how the arguments are supposed to be parsed
	// e.g. "-u UUID"
	GOptionContext *context;
	GOptionEntry entries[] = {
			{ "reprompt", 'r', 0, G_OPTION_ARG_NONE, &retry, "Reprompt for passwords", NULL},
			{ "uuid", 'u', 0, G_OPTION_ARG_STRING, &vpn_uuid, "UUID of VPN connection", NULL},
			{ "name", 'n', 0, G_OPTION_ARG_STRING, &vpn_name, "Name of VPN connection", NULL},
			{ "service", 's', 0, G_OPTION_ARG_STRING, &vpn_service, "VPN service type", NULL},
			{ "allow-interaction", 'i', 0, G_OPTION_ARG_NONE, &allow_interaction, "Allow user interaction", NULL},
			{ "external-ui-mode", 0, 0, G_OPTION_ARG_NONE, &external_ui_mode, "External UI mode", NULL},
			{ "hint", 't', 0, G_OPTION_ARG_STRING_ARRAY, &hints, "Hints from the VPN plugin", NULL},
			{ NULL }
		};

	bindtextdomain (GETTEXT_PACKAGE, NULL);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	gtk_init (&argc, &argv);

	context = g_option_context_new ("- openvpn auth dialog");
	g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);
	g_option_context_parse (context, &argc, &argv, NULL);
	g_option_context_free (context);

	if (vpn_uuid == NULL || vpn_name == NULL || vpn_service == NULL) {
		fprintf (stderr, "Have to supply ID, name, and service\n");
		return EXIT_FAILURE;
	}

	if (strcmp (vpn_service, NM_VPN_SERVICE_TYPE_WIREGUARD) != 0) {
		fprintf (stderr, "This dialog only works with the '%s' service\n", NM_VPN_SERVICE_TYPE_WIREGUARD);
		return EXIT_FAILURE;
	}

	// reads secrets/data from STDIN until "DONE" is read
	if (!nm_vpn_service_plugin_read_vpn_details (0, &data, &secrets)) {
		fprintf (stderr, "Failed to read '%s' (%s) data and secrets from stdin.\n",
		         vpn_name, vpn_uuid);
		return 1;
	}

	if (external_ui_mode) {
		no_secrets_required_func = eui_no_secrets_required;
		finish_func = eui_finish;
	} else {
		no_secrets_required_func = std_no_secrets_required;
		ask_user_func = std_ask_user;
		finish_func = std_finish;
	}

	/* Determine which passwords are actually required, either from hints or
	 * from looking at the VPN configuration.
	 */
	prompt = get_passwords_required (data, hints, &need_password, &need_certpass, &need_proxypass);
	if (!prompt)
		prompt = g_strdup_printf (_("You need to authenticate to access the Virtual Private Network “%s”."), vpn_name);

	/* Exit early if we don't need any passwords */
	if (!need_password && !need_certpass && !need_proxypass)
		no_secrets_required_func ();
	else {
		get_existing_passwords (data,
		                        secrets,
		                        vpn_uuid,
		                        need_password,
		                        need_certpass,
		                        need_proxypass,
		                        &existing_password,
		                        &existing_certpass,
		                        &existing_proxypass);
		if (need_password && !existing_password)
			ask_user = TRUE;
		if (need_certpass && !existing_certpass)
			ask_user = TRUE;
		if (need_proxypass && !existing_proxypass)
			ask_user = TRUE;

		/* If interaction is allowed then ask the user, otherwise pass back
		 * whatever existing secrets we can find.
		 */
		if (ask_user_func && allow_interaction && (ask_user || retry)) {
			canceled = !ask_user_func (vpn_name,
			                           prompt,
			                           need_password,
			                           existing_password,
			                           &new_password,
			                           need_certpass,
			                           existing_certpass,
			                           &new_certpass,
			                           need_proxypass,
			                           existing_proxypass,
			                           &new_proxypass);
		}

		if (!canceled) {
			finish_func (vpn_name,
			             prompt,
			             allow_interaction,
			             need_password,
			             new_password ? new_password : existing_password,
			             need_certpass,
			             new_certpass ? new_certpass : existing_certpass,
			             need_proxypass,
			             new_proxypass ? new_proxypass : existing_proxypass);
		}

		free_secret (existing_password);
		free_secret (existing_certpass);
		free_secret (existing_proxypass);
		free_secret (new_password);
		free_secret (new_certpass);
		free_secret (new_proxypass);
	}

	if (data)
		g_hash_table_unref (data);
	if (secrets)
		g_hash_table_unref (secrets);
	if (hints)
		g_strfreev (hints);
	g_free (prompt);
	return canceled ? 1 : 0;
}
