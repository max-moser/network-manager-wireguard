/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Copyright (C) 2009 Dan Williams, <dcbw@redhat.com>
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
 */

#include "nm-default.h"

#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <locale.h>
#include <sys/stat.h>

#include "nm-openvpn-editor-plugin.h"
#include "nm-openvpn-editor.h"
#include "import-export.h"
#include "utils.h"

#include "nm-utils/nm-test-utils.h"

#define SRCDIR TEST_SRCDIR"/conf"

#ifdef NM_VPN_OLD
#define TMPDIR TEST_BUILDDIR"/conf-tmp-old"
#else
#define TMPDIR TEST_BUILDDIR"/conf-tmp-new"
#endif

/*****************************************************************************/

static void
_test_nmovpn_remote_parse (const char *str,
                           const char *exp_host,
                           const char *exp_port,
                           const char *exp_proto)
{
	gs_free char *str_free = NULL;
	gssize r;
	const char *host, *port, *proto;
	gs_free_error GError *error = NULL;

	g_assert (exp_host || (!exp_port && !exp_proto));

	r = nmovpn_remote_parse (str, &str_free, &host, &port, &proto, &error);
	if (!exp_host) {
		g_assert (r >= 0);
		g_assert (error);
		return;
	}
	nmtst_assert_success (r == -1, error);

	g_assert_cmpstr (exp_host, ==, host);
	g_assert_cmpstr (exp_port, ==, port);
	g_assert_cmpstr (exp_proto, ==, proto);
}

static void
test_nmovpn_remote_parse (void)
{
	_test_nmovpn_remote_parse ("a",                          "a",                      NULL,    NULL);
	_test_nmovpn_remote_parse ("a:",                         "a",                      NULL,    NULL);
	_test_nmovpn_remote_parse ("t::",                        "t",                      NULL,    NULL);
	_test_nmovpn_remote_parse ("a::",                        "a::",                    NULL,    NULL);
	_test_nmovpn_remote_parse ("[a::]:",                     "a::",                    NULL,    NULL);
	_test_nmovpn_remote_parse ("t:::",                       "t:",                     NULL,    NULL);
	_test_nmovpn_remote_parse ("a:::",                       "a::",                    NULL,    NULL);
	_test_nmovpn_remote_parse ("a:t::",                      "a:t",                    NULL,    NULL);
	_test_nmovpn_remote_parse ("a:b::",                      "a:b::",                  NULL,    NULL);
	_test_nmovpn_remote_parse ("a::udp",                     "a",                      NULL,    "udp");
	_test_nmovpn_remote_parse ("a:1:",                       "a",                      "1",     NULL);
	_test_nmovpn_remote_parse ("t::1:",                      "t:",                     "1",     NULL);
	_test_nmovpn_remote_parse ("t::1:",                      "t:",                     "1",     NULL);
	_test_nmovpn_remote_parse ("[a:]:1:",                    "[a:]",                   "1",     NULL);
	_test_nmovpn_remote_parse ("a::1:",                      "a::1",                   NULL,    NULL);
	_test_nmovpn_remote_parse ("a::1:1194",                  "a::1:1194",              NULL,    NULL);
	_test_nmovpn_remote_parse ("[a::1]:1194",                "a::1",                   "1194",  NULL);
	_test_nmovpn_remote_parse ("a::1194",                    "a::1194",                NULL,    NULL);
	_test_nmovpn_remote_parse ("a::1194:",                   "a::1194",                NULL,    NULL);
	_test_nmovpn_remote_parse ("[a:]:1194:",                 "[a:]",                   "1194",  NULL);
	_test_nmovpn_remote_parse ("a:1:tcp",                    "a",                      "1",     "tcp");
	_test_nmovpn_remote_parse ("aa:bb::1:1194:udp",          NULL,                     NULL,    NULL);
	_test_nmovpn_remote_parse ("[aa:bb::1]:1194:udp",        "aa:bb::1",               "1194",  "udp");
	_test_nmovpn_remote_parse ("[aa:bb::1]::udp",            "aa:bb::1",               NULL,    "udp");
	_test_nmovpn_remote_parse ("aa:bb::1::udp",              "aa:bb::1",               NULL,    "udp");
	_test_nmovpn_remote_parse ("aa:bb::1::",                 "aa:bb::1",               NULL,    NULL);
	_test_nmovpn_remote_parse ("abc.com:1234:udp",           "abc.com",                "1234",  "udp");
	_test_nmovpn_remote_parse ("ovpnserver.company.com:443", "ovpnserver.company.com", "443",   NULL);
	_test_nmovpn_remote_parse ("vpn.example.com::tcp",       "vpn.example.com",        NULL,    "tcp");
	_test_nmovpn_remote_parse ("dead:beef::1:1194",          "dead:beef::1:1194",      NULL,    NULL);
	_test_nmovpn_remote_parse ("dead:beef::1:1194",          "dead:beef::1:1194",      NULL,    NULL);
	_test_nmovpn_remote_parse ("2001:dead:beef::1194::",     "2001:dead:beef::1194",   NULL,    NULL);
}

/*****************************************************************************/

static NMVpnEditorPlugin *
_create_plugin (void)
{
	NMVpnEditorPlugin *plugin;
	GError *error = NULL;

	plugin = nm_vpn_editor_plugin_factory (&error);
	g_assert_no_error (error);
	g_assert (OPENVPN_IS_EDITOR_PLUGIN (plugin));
	return plugin;
}
#define _CREATE_PLUGIN(plugin) \
	gs_unref_object NMVpnEditorPlugin *plugin = _create_plugin ()

/*****************************************************************************/

static NMConnection *
get_basic_connection (NMVpnEditorPlugin *plugin,
                      const char *dir,
                      const char *filename)
{
	NMConnection *connection;
	GError *error = NULL;
	char *pcf;

	pcf = g_build_path ("/", dir, filename, NULL);
	g_assert (pcf);

	connection = nm_vpn_editor_plugin_import (plugin, pcf, &error);
	g_assert_no_error (error);
	g_assert (connection);

	g_free (pcf);
	return connection;
}

#define _check_item(s_vpn, item, expected) \
	G_STMT_START { \
		NMSettingVpn *_s_vpn = (s_vpn); \
		\
		g_assert (_s_vpn); \
		g_assert_cmpstr (nm_setting_vpn_get_data_item (_s_vpn, (item)), ==, (expected)); \
	} G_STMT_END

#define _check_secret(s_vpn, item, expected) \
	G_STMT_START { \
		NMSettingVpn *_s_vpn = (s_vpn); \
		\
		g_assert (_s_vpn); \
		g_assert_cmpstr (nm_setting_vpn_get_secret (_s_vpn, (item)), ==, (expected)); \
	} G_STMT_END

/*****************************************************************************/

static void
test_password_import (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	char *expected_cacert;

	connection = get_basic_connection (plugin, SRCDIR, "password.conf");
	g_assert (connection);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "password");
	g_assert (!nm_setting_connection_get_uuid (s_con));

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	/* Data items */
	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_PASSWORD);
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_FLOAT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, "0");
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE, "test.server.com:443");
	_check_item (s_vpn, NM_OPENVPN_KEY_PORT, "2352");
	_check_item (s_vpn, NM_OPENVPN_KEY_CERT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA_DIR, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_CIPHER, "AES-256-CBC");
	_check_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);

	expected_cacert = g_build_filename (SRCDIR, "cacert.pem", NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_CA, expected_cacert);
	g_free (expected_cacert);

	/* Secrets */
	_check_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD, NULL);
	_check_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS, NULL);

	g_object_unref (connection);
}

static void
save_one_key (const char *key, const char *value, gpointer user_data)
{
	GSList **list = user_data;

	*list = g_slist_append (*list, g_strdup (key));
}

static void
remove_secrets (NMConnection *connection)
{
	NMSettingVpn *s_vpn;
	GSList *keys = NULL, *iter;

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn)
		return;

	nm_setting_vpn_foreach_secret (s_vpn, save_one_key, &keys);
	for (iter = keys; iter; iter = g_slist_next (iter))
		nm_setting_vpn_remove_secret (s_vpn, (const char *) iter->data);

	g_slist_foreach (keys, (GFunc) g_free, NULL);
	g_slist_free (keys);
}

static void
test_export_compare (gconstpointer test_data)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMConnection *reimported;
	char *path;
	gboolean success;
	GError *error = NULL;
	const char *file, *exported_name;

	nmtst_test_data_unpack (test_data, &file, &exported_name);

	connection = get_basic_connection (plugin, SRCDIR, file);
	g_assert (connection);

	path = g_build_path ("/", TMPDIR, exported_name, NULL);
	success = nm_vpn_editor_plugin_export (plugin, path, connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection (plugin, TMPDIR, exported_name);
	(void) unlink (path);
	g_assert (reimported);

	/* Clear secrets first, since they don't get exported, and thus would
	 * make the connection comparison below fail.
	 */
	remove_secrets (connection);
	g_assert (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT));

	g_object_unref (reimported);
	g_object_unref (connection);
	g_free (path);
}

static void
test_tls_import (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	char *expected_path;

	connection = get_basic_connection (plugin, SRCDIR, "tls.ovpn");
	g_assert (connection);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "tls");
	g_assert (!nm_setting_connection_get_uuid (s_con));

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	/* Data items */
	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_TLS);
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, "adaptive");
	_check_item (s_vpn, NM_OPENVPN_KEY_FLOAT, "yes");
	_check_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE, "173.8.149.245:1194");
	_check_item (s_vpn, NM_OPENVPN_KEY_PORT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_CIPHER, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TLS_REMOTE, "/CN=myvpn.company.com");
	_check_item (s_vpn, NM_OPENVPN_KEY_VERIFY_X509_NAME,
	             "subject:C=US, L=Cambridge, CN=GNOME, emailAddress=networkmanager-list@gnome.org");
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_CERT_TLS, "server");

	expected_path = g_strdup_printf ("%s/keys/mg8.ca", SRCDIR);
	_check_item (s_vpn, NM_OPENVPN_KEY_CA, expected_path);
	g_free (expected_path);

	expected_path = g_strdup_printf ("%s/keys/clee.crt", SRCDIR);
	_check_item (s_vpn, NM_OPENVPN_KEY_CERT, expected_path);
	g_free (expected_path);

	expected_path = g_strdup_printf ("%s/keys/clee.key", SRCDIR);
	_check_item (s_vpn, NM_OPENVPN_KEY_KEY, expected_path);
	g_free (expected_path);

	expected_path = g_strdup_printf ("%s/keys/46.key", SRCDIR);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA, expected_path);
	g_free (expected_path);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA_DIR, "1");

	/* Secrets */
	_check_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD, NULL);
	_check_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS, NULL);

	g_object_unref (connection);
}

static void
test_tls_import_2 (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	char *expected_path;

	connection = get_basic_connection (plugin, SRCDIR, "tls2.ovpn");
	g_assert (connection);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "tls2");
	g_assert (!nm_setting_connection_get_uuid (s_con));

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	/* Data items */
	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_TLS);
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, "adaptive");
	_check_item (s_vpn, NM_OPENVPN_KEY_FLOAT, "yes");
	_check_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE, "173.8.149.245:1194");
	_check_item (s_vpn, NM_OPENVPN_KEY_PORT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_CIPHER, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TLS_REMOTE, "/CN=myvpn.company.com");
	_check_item (s_vpn, NM_OPENVPN_KEY_VERIFY_X509_NAME,
	             "subject:C=US, L=Cambridge, CN=GNOME, emailAddress=networkmanager-list@gnome.org");
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_CERT_TLS, "server");

	expected_path = g_strdup_printf ("%s/keys/mg8.ca", SRCDIR);
	_check_item (s_vpn, NM_OPENVPN_KEY_CA, expected_path);
	g_free (expected_path);

	expected_path = g_strdup_printf ("%s/keys/clee.crt", SRCDIR);
	_check_item (s_vpn, NM_OPENVPN_KEY_CERT, expected_path);
	g_free (expected_path);

	expected_path = g_strdup_printf ("%s/keys/clee.key", SRCDIR);
	_check_item (s_vpn, NM_OPENVPN_KEY_KEY, expected_path);
	g_free (expected_path);

	expected_path = g_strdup_printf ("%s/keys/46.key", SRCDIR);
	_check_item (s_vpn, NM_OPENVPN_KEY_TLS_CRYPT, expected_path);
	g_free (expected_path);

	/* Secrets */
	_check_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD, NULL);
	_check_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS, NULL);

	g_object_unref (connection);
}

static void
test_file_contents (const char *id,
                    const char *dir,
                    NMSettingVpn *s_vpn,
                    char *item) {
	const char *path;
	char *path2;
	char *contents;
	char *expected_contents;
	gsize length;
	gsize expected_length;
	char *test;

	test = g_strdup_printf("%s-%s", id, item);

	path = nm_setting_vpn_get_data_item(s_vpn, item);
	g_assert (g_file_get_contents (path, &contents, &length, NULL));

	path2 = g_strdup_printf ("%s/%s-%s.pem", dir, id, item);
	g_assert (g_file_get_contents (path2, &expected_contents, &expected_length, NULL));

	g_assert_cmpmem (contents, length, expected_contents, expected_length);

	g_free (contents);
	g_free (expected_contents);
	g_free (path2);
	g_free (test);
}

static void
test_tls_inline_import (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	const char *expected_id = "tls-inline";

	connection = get_basic_connection (plugin, SRCDIR, "tls-inline.ovpn");
	g_assert (connection);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert (!nm_setting_connection_get_uuid (s_con));

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	/* Data items */
	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_TLS);
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, "adaptive");
	_check_item (s_vpn, NM_OPENVPN_KEY_FLOAT, "yes");
	_check_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE, "173.8.149.245:1194");
	_check_item (s_vpn, NM_OPENVPN_KEY_PORT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_CIPHER, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TLS_REMOTE, "/CN=myvpn.company.com");
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_CERT_TLS, "server");

	test_file_contents (expected_id, SRCDIR, s_vpn, NM_OPENVPN_KEY_CA);
	test_file_contents (expected_id, SRCDIR, s_vpn, NM_OPENVPN_KEY_CERT);
	test_file_contents (expected_id, SRCDIR, s_vpn, NM_OPENVPN_KEY_KEY);
	test_file_contents (expected_id, SRCDIR, s_vpn, NM_OPENVPN_KEY_TA);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA_DIR, "1");

	_check_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD, NULL);
	_check_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS, NULL);

	g_assert (unlink (TMPDIR"/tls-inline-ca.pem") == 0);
	g_assert (unlink (TMPDIR"/tls-inline-cert.pem") == 0);
	g_assert (unlink (TMPDIR"/tls-inline-key.pem") == 0);
	g_assert (unlink (TMPDIR"/tls-inline-tls-auth.pem") == 0);

	g_object_unref (connection);
}

static void
test_pkcs12_import (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	const char *expected_id = "pkcs12";
	char *expected_path;

	connection = get_basic_connection (plugin, SRCDIR, "pkcs12.ovpn");
	g_assert (connection);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert (!nm_setting_connection_get_uuid (s_con));

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	/* Data items */
	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_TLS);
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, "adaptive");
	_check_item (s_vpn, NM_OPENVPN_KEY_FLOAT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE, "173.8.149.245:1194");
	_check_item (s_vpn, NM_OPENVPN_KEY_PORT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_CIPHER, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);

	expected_path = g_strdup_printf ("%s/keys/mine.p12", SRCDIR);
	_check_item (s_vpn, NM_OPENVPN_KEY_CA, expected_path);
	g_free (expected_path);

	expected_path = g_strdup_printf ("%s/keys/mine.p12", SRCDIR);
	_check_item (s_vpn, NM_OPENVPN_KEY_CERT, expected_path);
	g_free (expected_path);

	expected_path = g_strdup_printf ("%s/keys/mine.p12", SRCDIR);
	_check_item (s_vpn, NM_OPENVPN_KEY_KEY, expected_path);
	g_free (expected_path);

	/* Secrets */
	_check_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD, NULL);
	_check_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS, NULL);

	g_object_unref (connection);
}

static void
test_non_utf8_import (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	char *expected_path;
	const char *charset = NULL;

	/* Change charset to ISO-8859-15 to match iso885915.ovpn */
	g_get_charset (&charset);
	setlocale (LC_ALL, "de_DE@euro");
	connection = get_basic_connection (plugin, SRCDIR, "iso885915.ovpn");
	setlocale (LC_ALL, charset);
	g_assert (connection);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "iso885915");
	g_assert (!nm_setting_connection_get_uuid (s_con));

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	expected_path = g_strdup_printf ("%s/%s", SRCDIR, "Att\\344taenko.pem");
	_check_item (s_vpn, NM_OPENVPN_KEY_CA, expected_path);
	g_free (expected_path);

	g_object_unref (connection);
}

static void
test_static_key_import (gconstpointer test_data)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	const char *file, *expected_id, *expected_dir;
	char *expected_path;

	nmtst_test_data_unpack (test_data, &file, &expected_id, &expected_dir);

	connection = get_basic_connection (plugin, SRCDIR, file);
	g_assert (connection);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert (!nm_setting_connection_get_uuid (s_con));

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	/* Data items */
	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_STATIC_KEY);
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_FLOAT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE, "10.11.12.13");
	_check_item (s_vpn, NM_OPENVPN_KEY_PORT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, expected_dir);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA_DIR, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_CIPHER, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, "10.8.0.2");
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, "10.8.0.1");
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);

	expected_path = g_strdup_printf ("%s/static.key", SRCDIR);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, expected_path);
	g_free (expected_path);

	/* Secrets */
	_check_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD, NULL);
	_check_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS, NULL);

	g_object_unref (connection);
}

static void
test_port_import (gconstpointer test_data)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	const char *file, *expected_id, *expected_port;

	nmtst_test_data_unpack (test_data, &file, &expected_id, &expected_port);

	connection = get_basic_connection (plugin, SRCDIR, file);
	g_assert (connection);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	/* Data items */
	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_TLS);
	_check_item (s_vpn, NM_OPENVPN_KEY_PORT, expected_port);

	g_object_unref (connection);
}

static void
test_ping_import (gconstpointer test_data)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	const char *file, *expected_ping, *expected_ping_exit, *expected_ping_restart;

	nmtst_test_data_unpack (test_data, &file, &expected_ping, &expected_ping_exit, &expected_ping_restart);

	connection = get_basic_connection (plugin, SRCDIR, file);
	g_assert (connection);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	/* Data items */
	_check_item (s_vpn, NM_OPENVPN_KEY_PING, expected_ping);
	_check_item (s_vpn, NM_OPENVPN_KEY_PING_EXIT, expected_ping_exit);
	_check_item (s_vpn, NM_OPENVPN_KEY_PING_RESTART, expected_ping_restart);

	g_object_unref (connection);
}

static void
test_tun_opts_import (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "tun-opts.conf");
	g_assert (connection);

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	/* Data items */
	_check_item (s_vpn, NM_OPENVPN_KEY_MSSFIX, "yes");
	_check_item (s_vpn, NM_OPENVPN_KEY_TUNNEL_MTU, "1300");
	_check_item (s_vpn, NM_OPENVPN_KEY_FRAGMENT_SIZE, "1200");

	g_object_unref (connection);
}

static void
test_proxy_http_import (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "proxy-http.ovpn");
	g_assert (connection);

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	/* Data items */
	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_PASSWORD);
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, "yes");
	_check_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_FLOAT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, "0");
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE, "[aa:bb::1]:1194:udp");
	_check_item (s_vpn, NM_OPENVPN_KEY_PORT, "2352");
	_check_item (s_vpn, NM_OPENVPN_KEY_CERT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA_DIR, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_CIPHER, "AES-256-CBC");
	_check_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_PROXY_TYPE, "http");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROXY_SERVER, "10.1.1.1");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROXY_PORT, "8080");
	_check_item (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_USERNAME, "myusername");
	_check_secret (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD, "mypassword");

	g_object_unref (connection);
}

#define PROXY_HTTP_EXPORTED_NAME "proxy-http.ovpntest"
static void
test_proxy_http_export (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMConnection *reimported;
	char *path;
	gboolean success;
	GError *error = NULL;

	connection = get_basic_connection (plugin, SRCDIR, "proxy-http.ovpn");
	g_assert (connection);

	path = g_build_path ("/", TMPDIR, PROXY_HTTP_EXPORTED_NAME, NULL);
	success = nm_vpn_editor_plugin_export (plugin, path, connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection (plugin, TMPDIR, PROXY_HTTP_EXPORTED_NAME);
	(void) unlink (path);
	g_free (path);
	g_assert (reimported);

	g_assert (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT));

	/* Unlink the proxy authfile */
	path = g_strdup_printf ("%s/%s-httpauthfile", TMPDIR, PROXY_HTTP_EXPORTED_NAME);
	(void) unlink (path);
	g_free (path);

	g_object_unref (reimported);
	g_object_unref (connection);
}

static void
test_proxy_http_with_auth_import (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "proxy-http-with-auth.ovpn");
	g_assert (connection);

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	/* Data items */
	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_PASSWORD);
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, "yes");
	_check_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_FLOAT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, "0");
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE, "test.server.com:443");
	_check_item (s_vpn, NM_OPENVPN_KEY_PORT, "2352");
	_check_item (s_vpn, NM_OPENVPN_KEY_CERT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA_DIR, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_CIPHER, "AES-256-CBC");
	_check_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_PROXY_TYPE, "http");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROXY_SERVER, "proxy.domain.tld");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROXY_PORT, "3128");
	_check_item (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_USERNAME, "myusername");
	_check_secret (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD, "mypassword");

	g_object_unref (connection);
}

static void
test_proxy_socks_import (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "proxy-socks.ovpn");
	g_assert (connection);

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	/* Data items */
	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_PASSWORD);
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, "yes");
	_check_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_FLOAT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, "0");
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE, "test.server.com:443");
	_check_item (s_vpn, NM_OPENVPN_KEY_PORT, "2352");
	_check_item (s_vpn, NM_OPENVPN_KEY_CERT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA_DIR, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_CIPHER, "AES-256-CBC");
	_check_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_PROXY_TYPE, "socks");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROXY_SERVER, "10.1.1.1");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROXY_PORT, "1080");

	g_object_unref (connection);
}

static void
test_keysize_import (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "keysize.ovpn");
	g_assert (connection);

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	/* Data items */
	_check_item (s_vpn, NM_OPENVPN_KEY_KEYSIZE, "512");

	g_object_unref (connection);
}

static void
test_device_import (gconstpointer test_data)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingVpn *s_vpn;
	const char *file, *expected_dev, *expected_devtype;

	nmtst_test_data_unpack (test_data, &file, &expected_dev, &expected_devtype);

	connection = get_basic_connection (plugin, SRCDIR, file);
	g_assert (connection);

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	/* Data items */
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV, expected_dev);
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV_TYPE, expected_devtype);

	g_object_unref (connection);
}

static void
test_mtu_disc_import (gconstpointer test_data)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingVpn *s_vpn;
	const char *file, *expected_val;

	nmtst_test_data_unpack (test_data, &file, &expected_val);

	connection = get_basic_connection (plugin, SRCDIR, file);
	g_assert (connection);

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	/* Data items */
	_check_item (s_vpn, NM_OPENVPN_KEY_MTU_DISC, expected_val);

	g_object_unref (connection);
}

static void
test_route_import (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingVpn *s_vpn;
	int num_routes;
	const char *expected_dest1 = "1.2.3.0";
	guint32 expected_prefix1   = 24;
	const char *expected_nh1   = "1.2.3.254";
	gint64 expected_metric1    = 99;
	const char *expected_dest2 = "5.6.7.8";
	guint32 expected_prefix2   = 30;
	gint64 expected_metric2    = -1;
	const char *expected_dest3 = "192.168.0.0";
	guint32 expected_prefix3   = 16;
	const char *expected_nh3   = "192.168.44.1";
	gint64 expected_metric3    = -1;

	connection = get_basic_connection (plugin, SRCDIR, "route.ovpn");
	g_assert (connection);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	/* Data items */
	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_TLS);

	/* IP4 setting */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
#ifdef NM_VPN_OLD
	{
		NMIP4Route *route;
		const char *expected_nh2   = "0.0.0.0";

#define METR(metr) ((metr) == -1 ? 0 : ((guint32) (metr)))

		num_routes = nm_setting_ip4_config_get_num_routes (s_ip4);
		g_assert_cmpint (num_routes, ==, 3);

		/* route 1 */
		route = nm_setting_ip4_config_get_route (s_ip4, 0);
		g_assert_cmpint (nm_ip4_route_get_dest (route), ==, nmtst_inet4_from_string (expected_dest1));
		g_assert_cmpint (nm_ip4_route_get_prefix (route), ==, expected_prefix1);
		g_assert_cmpint (nm_ip4_route_get_next_hop (route), ==, nmtst_inet4_from_string (expected_nh1));
		g_assert_cmpint (nm_ip4_route_get_metric (route), ==, METR (expected_metric1));

		/* route 2 */
		route = nm_setting_ip4_config_get_route (s_ip4, 1);
		g_assert_cmpint (nm_ip4_route_get_dest (route), ==, nmtst_inet4_from_string (expected_dest2));
		g_assert_cmpint (nm_ip4_route_get_prefix (route), ==, expected_prefix2);
		g_assert_cmpint (nm_ip4_route_get_next_hop (route), ==, nmtst_inet4_from_string (expected_nh2));
		g_assert_cmpint (nm_ip4_route_get_metric (route), ==, METR (expected_metric2));

		/* route 3 */
		route = nm_setting_ip4_config_get_route (s_ip4, 2);
		g_assert_cmpint (nm_ip4_route_get_dest (route), ==, nmtst_inet4_from_string (expected_dest3));
		g_assert_cmpint (nm_ip4_route_get_prefix (route), ==, expected_prefix3);
		g_assert_cmpint (nm_ip4_route_get_next_hop (route), ==, nmtst_inet4_from_string (expected_nh3));
		g_assert_cmpint (nm_ip4_route_get_metric (route), ==, METR (expected_metric3));
	}
#else
	{
		NMIPRoute *route;

		num_routes = nm_setting_ip_config_get_num_routes (s_ip4);
		g_assert_cmpint (num_routes, ==, 3);

		/* route 1 */
		route = nm_setting_ip_config_get_route (s_ip4, 0);
		g_assert_cmpstr (nm_ip_route_get_dest (route), ==, expected_dest1);
		g_assert_cmpint (nm_ip_route_get_prefix (route), ==, expected_prefix1);
		g_assert_cmpstr (nm_ip_route_get_next_hop (route), ==, expected_nh1);
		g_assert_cmpint (nm_ip_route_get_metric (route), ==, expected_metric1);

		/* route 2 */
		route = nm_setting_ip_config_get_route (s_ip4, 1);
		g_assert_cmpstr (nm_ip_route_get_dest (route), ==, expected_dest2);
		g_assert_cmpint (nm_ip_route_get_prefix (route), ==, expected_prefix2);
		g_assert_cmpstr (nm_ip_route_get_next_hop (route), ==, NULL);
		g_assert_cmpint (nm_ip_route_get_metric (route), ==, expected_metric2);

		/* route 3 */
		route = nm_setting_ip_config_get_route (s_ip4, 2);
		g_assert_cmpstr (nm_ip_route_get_dest (route), ==, expected_dest3);
		g_assert_cmpint (nm_ip_route_get_prefix (route), ==, expected_prefix3);
		g_assert_cmpstr (nm_ip_route_get_next_hop (route), ==, expected_nh3);
		g_assert_cmpint (nm_ip_route_get_metric (route), ==, expected_metric3);
	}
#endif

	g_object_unref (connection);
}

/*****************************************************************************/

static void
do_test_args_parse_impl (const char *line,
                         gboolean expects_success,
                         ...)
{
	va_list ap;
	guint i;
	const char *s;
	const char *expected_str[100] = { NULL };
	gboolean again = TRUE;
	gs_free char *line_again = NULL;
	gsize len;

	va_start (ap, expects_success);
	i = 0;
	do {
		s = va_arg (ap, const char *);
		g_assert (i < G_N_ELEMENTS (expected_str));
		expected_str[i++] = s;
	} while (s);
	va_end (ap);

	len = strlen (line);

do_again:
	{
		gs_free const char **p = NULL;
		gs_free char *line_error = NULL;

		if (!_nmovpn_test_args_parse_line (line, len, &p, &line_error)) {
			g_assert (!expects_success);
			g_assert (line_error && line_error[0]);
			g_assert (!p);
		} else {
			g_assert (expects_success);
			g_assert (!line_error);

			if (expected_str[0] == NULL) {
				g_assert (!p);
			} else {
				g_assert (p);
				for (i = 0; TRUE; i++) {
					g_assert_cmpstr (p[i], ==, expected_str[i]);
					if (expected_str[i] == NULL)
						break;
					if (i > 0)
						g_assert (p[i] == &((p[i - 1])[strlen (p[i - 1]) + 1]));
				}
				g_assert (p[0] == (const char *) (&p[i + 1]));
			}
		}
	}

	if (again) {
		/* append some gibberish. Ensure it's ignored. */
		line = line_again = g_strconcat (line, "X", NULL);
		again = FALSE;
		goto do_again;
	}
}
#define do_test_args_parse_line(...) do_test_args_parse_impl (__VA_ARGS__, NULL)

static void
test_args_parse_line (void)
{
	do_test_args_parse_line ("", TRUE);
	do_test_args_parse_line ("  ", TRUE);
	do_test_args_parse_line (" \t", TRUE);
	do_test_args_parse_line (" \r", TRUE);
	do_test_args_parse_line ("a", TRUE, "a");
	do_test_args_parse_line (" ba ", TRUE, "ba");
	do_test_args_parse_line (" b  a ", TRUE, "b", "a");
	do_test_args_parse_line (" b \\ \\a ", TRUE, "b", " a");
	do_test_args_parse_line ("\\ b \\ \\a ", TRUE, " b", " a");
	do_test_args_parse_line ("'\\ b \\ \\a '", TRUE, "\\ b \\ \\a ");
	do_test_args_parse_line ("\"\\ b \\ \\a \"a'b'", TRUE, " b  a ", "a'b'");
	do_test_args_parse_line ("\"\\ b \\ \\a \"a\\ 'b'", TRUE, " b  a ", "a 'b'");
	do_test_args_parse_line ("\"\\ b \\ \\a \"a\\ 'b'   sd\\ \t", TRUE, " b  a ", "a 'b'", "sd ");

	do_test_args_parse_line ("\"adfdaf  adf  ", FALSE);
	do_test_args_parse_line ("\"adfdaf  adf  \\\"", FALSE);
	do_test_args_parse_line ("\"\\ b \\ \\a \"a\\ 'b'   sd\\", FALSE);
}

/*****************************************************************************/

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	int errsv, result;

	_nmovpn_test_temp_path = TMPDIR;

	nmtst_init (&argc, &argv, TRUE);

	if (mkdir (TMPDIR, 0755) != 0) {
		errsv = errno;
		if (errsv != EEXIST)
			g_error ("failed creating \"%s\": %s", TMPDIR, g_strerror (errsv));
	}

#define _add_test_func_simple(func)       g_test_add_func ("/ovpn/properties/" #func, func)
#define _add_test_func(detail, func, ...) nmtst_add_test_func ("/ovpn/properties/" detail, func, ##__VA_ARGS__)

	_add_test_func_simple (test_nmovpn_remote_parse);

	_add_test_func_simple (test_password_import);
	_add_test_func ("password-export", test_export_compare, "password.conf", "password.ovpntest");

	_add_test_func_simple (test_tls_import);
	_add_test_func_simple (test_tls_inline_import);
	_add_test_func ("tls-export", test_export_compare, "tls.ovpn", "tls.ovpntest");

	_add_test_func_simple (test_tls_import_2);
	_add_test_func ("tls2-export", test_export_compare, "tls2.ovpn", "tls2.ovpntest");

	_add_test_func_simple (test_pkcs12_import);
	_add_test_func ("pkcs12-export", test_export_compare, "pkcs12.ovpn", "pkcs12.ovpntest");

	_add_test_func_simple (test_non_utf8_import);

	_add_test_func ("static-import-1", test_static_key_import, "static.ovpn", "static", "1");
	_add_test_func ("static-import-2", test_static_key_import, "static2.ovpn", "static2", "0");
	_add_test_func ("static", test_export_compare, "static.ovpn", "static.ovpntest");

	_add_test_func ("port-import", test_port_import, "port.ovpn", "port", "2345");
	_add_test_func ("port-export", test_export_compare, "port.ovpn", "port.ovpntest");

	_add_test_func ("rport-import", test_port_import, "rport.ovpn", "rport", "6789");
	_add_test_func ("rport-export", test_export_compare, "rport.ovpn", "rport.ovpntest");

	_add_test_func_simple (test_tun_opts_import);
	_add_test_func ("tun-opts-export", test_export_compare, "tun-opts.conf", "tun-opts.ovpntest");

	_add_test_func ("ping-with-exit-import", test_ping_import, "ping-with-exit.ovpn", "10", "120", NULL);
	_add_test_func ("ping-with-restart-import", test_ping_import, "ping-with-restart.ovpn", "10", NULL, "30");

	_add_test_func ("ping-with-exit-export", test_export_compare, "ping-with-exit.ovpn", "ping-with-exit.ovpntest");
	_add_test_func ("ping-with-restart-export", test_export_compare, "ping-with-restart.ovpn", "ping-with-restart.ovpntest");

	_add_test_func ("keepalive-import", test_ping_import, "keepalive.ovpn", "10", NULL, "30");
	_add_test_func ("keepalive-export", test_export_compare, "keepalive.ovpn", "keepalive.ovpntest");

	_add_test_func_simple (test_proxy_http_import);
	_add_test_func_simple (test_proxy_http_export);

	_add_test_func_simple (test_proxy_http_with_auth_import);

	_add_test_func_simple (test_proxy_socks_import);
	_add_test_func ("proxy-socks-export", test_export_compare, "proxy-socks.ovpn", "proxy-socks.ovpntest");

	_add_test_func_simple (test_keysize_import);
	_add_test_func ("keysize-export", test_export_compare, "keysize.ovpn", "keysize.ovpntest");

	_add_test_func ("device-import-default", test_device_import, "device.ovpn", "company0", "tun");
	_add_test_func ("device-export-default", test_export_compare, "device.ovpn", "device.ovpntest");

	_add_test_func ("device-import-notype", test_device_import, "device-notype.ovpn", "tap", NULL);
	_add_test_func ("device-export-notype", test_export_compare, "device-notype.ovpn", "device-notype.ovpntest");

	_add_test_func ("mtu-disc-import", test_mtu_disc_import, "mtu-disc.ovpn", "yes");
	_add_test_func ("mtu-disc-export", test_export_compare, "mtu-disc.ovpn", "mtu-disc.ovpntest");

	_add_test_func_simple (test_route_import);
	_add_test_func ("route-export", test_export_compare, "route.ovpn", "route.ovpntest");

	_add_test_func_simple (test_args_parse_line);

	result = g_test_run ();
	if (result != EXIT_SUCCESS)
		return result;

	if (rmdir (TMPDIR) != 0) {
		errsv = errno;
		g_error ("failed deleting %s: %s", TMPDIR, g_strerror (errsv));
	}

	return EXIT_SUCCESS;
}

