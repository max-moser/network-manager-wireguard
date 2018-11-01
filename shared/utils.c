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

#include "nm-default.h"

#include "utils.h"

#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "nm-utils/nm-shared-utils.h"

gboolean
is_pkcs12 (const char *filepath)
{
	NMSetting8021xCKFormat ck_format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	NMSetting8021x *s_8021x;

	if (!filepath || !strlen (filepath))
		return FALSE;

	if (!g_file_test (filepath, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))
		return FALSE;

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	g_return_val_if_fail (s_8021x != NULL, FALSE);

	nm_setting_802_1x_set_private_key (s_8021x,
	                                   filepath,
	                                   NULL,
	                                   NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                   &ck_format,
	                                   NULL);
	g_object_unref (s_8021x);

	return (ck_format == NM_SETTING_802_1X_CK_FORMAT_PKCS12);
}

#define PROC_TYPE_TAG "Proc-Type: 4,ENCRYPTED"
#define PKCS8_TAG "-----BEGIN ENCRYPTED PRIVATE KEY-----"

/** Checks if a file appears to be an encrypted private key.
 * @param filename the path to the file
 * @return returns true if the key is encrypted, false otherwise
 */
gboolean
is_encrypted (const char *filename)
{
	GIOChannel *pem_chan;
	char *str = NULL;
	gboolean encrypted = FALSE;

	if (!filename || !strlen (filename))
		return FALSE;

	if (is_pkcs12 (filename))
		return TRUE;

	pem_chan = g_io_channel_new_file (filename, "r", NULL);
	if (!pem_chan)
		return FALSE;

	while (g_io_channel_read_line (pem_chan, &str, NULL, NULL, NULL) != G_IO_STATUS_EOF) {
		if (str) {
			if (g_str_has_prefix (str, PROC_TYPE_TAG) || g_str_has_prefix (str, PKCS8_TAG)) {
				encrypted = TRUE;
				break;
			}
			g_free (str);
		}
	}

	g_io_channel_shutdown (pem_chan, FALSE, NULL);
	g_io_channel_unref (pem_chan);
	return encrypted;
}

static gboolean
_is_inet6_addr (const char *str, gboolean with_square_brackets)
{
	struct in6_addr a;
	gsize l;

	if (   with_square_brackets
	    && str[0] == '[') {
		l = strlen (str);
		if (str[l - 1] == ']') {
			gs_free char *s = g_strndup (&str[1], l - 2);

			return inet_pton (AF_INET6, s, &a) == 1;
		}
	}
	return inet_pton (AF_INET6, str, &a) == 1;
}

/**
 * nmovpn_remote_parse:
 * @str: the input string to be split. It is modified inplace.
 * @out_buf: an allocated string, to which the other arguments
 *   point to. Must be freeded by caller.
 * @out_host: pointer to the host out argument.
 * @out_port: pointer to the port out argument.
 * @out_proto: pointer to the proto out argument.
 * @error:
 *
 * Splits @str in three parts host, port and proto.
 *
 * Returns: -1 on success or index in @str of first invalid character.
 *  Note that the error index can be at strlen(str), if some data is missing.
 **/
gssize
nmovpn_remote_parse (const char *str,
                     char **out_buf,
                     const char **out_host,
                     const char **out_port,
                     const char **out_proto,
                     GError **error)
{
	gs_free char *str_copy = NULL;
	char *t;
	char *host = NULL;
	char *port = NULL;
	char *proto = NULL;
	gssize idx_fail;

	g_return_val_if_fail (str, 0);
	if (!out_buf) {
		/* one can omit @out_buf only if also no other out-arguments
		 * are requested. */
		if (out_host || out_port || out_proto)
			g_return_val_if_reached (0);
	}
	g_return_val_if_fail (!error || !*error, 0);

	t = strchr (str, ' ');
	if (!t)
		t = strchr (str, ',');
	if (t) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             _("invalid delimiter character '%c'"), t[0]);
		idx_fail = t - str;
		goto out_fail;
	}

	if (!g_utf8_validate (str, -1, (const char **) &t)) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             _("invalid non-utf-8 character"));
		idx_fail = t - str;
		goto out_fail;
	}

	str_copy = g_strdup (str);

	/* we already checked that there is no space above.
	 * Strip tabs nonetheless. */
	host = nm_str_skip_leading_spaces (str_copy);
	g_strchomp (host);

	t = strrchr (host, ':');
	if (   t
	    && !_is_inet6_addr (host, TRUE)) {
		t[0] = '\0';
		port = &t[1];
		t = strrchr (host, ':');
		if (   t
		    && !_is_inet6_addr (host, TRUE)) {
			t[0] = '\0';
			proto = port;
			port = &t[1];
		}
	}

	if (!host[0]) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             _("empty host"));
		idx_fail = host - str;
		goto out_fail;
	}
	if (port) {
		if (!port[0]) {
			/* allow empty port like "host::udp". */
			port = NULL;
		} else if (_nm_utils_ascii_str_to_int64 (port, 10, 1, 0xFFFF, 0) == 0) {
			g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
			             _("invalid port"));
			idx_fail = port - str;
			goto out_fail;
		}
	}
	if (proto) {
		if (!proto[0]) {
			/* allow empty proto, so that host can contain ':'. */
			proto = NULL;
		} else if (!NM_IN_STRSET (proto, NMOVPN_PROTCOL_TYPES)) {
			g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
			             _("invalid protocol"));
			idx_fail = proto - str;
			goto out_fail;
		}
	}

	if (out_buf) {
		*out_buf = g_steal_pointer (&str_copy);
		if (   host[0] == '['
		    && _is_inet6_addr (host, TRUE)
		    && !_is_inet6_addr (host, FALSE)) {
			gsize l;

			host++;
			l = strlen (host);
			nm_assert (l > 0 && host[l - 1] == ']');
			host[l - 1] = '\0';
			nm_assert (_is_inet6_addr (host, FALSE));
		}
		NM_SET_OUT (out_host, host);
		NM_SET_OUT (out_port, port);
		NM_SET_OUT (out_proto, proto);
	}
	return -1;

out_fail:
	if (out_buf) {
		*out_buf = NULL;
		NM_SET_OUT (out_host, NULL);
		NM_SET_OUT (out_port, NULL);
		NM_SET_OUT (out_proto, NULL);
	}
	return idx_fail;
}

/*****************************************************************************/

// check if the given string is NULL or empty
gboolean
is_empty(const char *str)
{
	gboolean empty = FALSE;
	gchar *tmp = g_strdup(str);
	tmp = g_strstrip(tmp);

	if(!tmp || !tmp[0]){
		empty = TRUE;
	}

	g_free(tmp);
	return empty;
}

// check if the given string looks like an IPv4 address
// that is, four segments of numbers (0-255), separated by dots
// additionally, there may be a port suffix (separated from the address by a colon; 0 - 65535)
// and/or a subnet (separated by the rest by a slash; 0 - 32)
gboolean
is_ip4(char *addr)
{
	int idx = 0;
	int dots = 0;
	gchar **parts;
	gchar **tmp;
	gchar **tmp2;
	gchar *lastpart;
	gboolean success = TRUE;

	if(!addr){
		return FALSE;
	}

	while(addr && addr[idx]){
		if(addr[idx] == '.'){
			dots++;
		}
		idx++;
	}

	if(dots != 3){
		return FALSE;
	}

	parts = g_strsplit(addr, ".", 0);

	// iterate over the first three parts, which cannot be anything else than numbers
	for(idx = 0; idx < 3; idx++){
		if(!g_ascii_string_to_unsigned(parts[idx], 10, 0, 255, NULL, NULL)){
			success = FALSE;
			goto ip4end;
		}
	}

	// if the last part is a number, we're fine
	lastpart = parts[3];
	if(g_ascii_string_to_unsigned(lastpart, 10, 0, 255, NULL, NULL)){
		success = TRUE;
		goto ip4end;
	}

	// might have a subnet suffix after a slash (e.g. 192.168.1.254/24)
	// might have a port suffix after a colon (e.g. 192.168.1.254:8080)
	if(g_strrstr(lastpart, ":") && g_strrstr(lastpart, "/")){
		tmp = g_strsplit(lastpart, ":", 2);
		tmp2 = g_strsplit(tmp[1], "/", 2);

		if(!g_ascii_string_to_unsigned(tmp[0], 10, 0, 255, NULL, NULL)){
			// the last part of the IP
			success = FALSE;
		}

		if(!g_ascii_string_to_unsigned(tmp2[0], 10, 0, 65535, NULL, NULL)){
			// the port
			success = FALSE;
		}

		if(!g_ascii_string_to_unsigned(tmp2[1], 10, 0, 32, NULL, NULL)){
			// the subnet portion
			success = FALSE;
		}

		g_strfreev(tmp);
		g_strfreev(tmp2);
	}
	else if(g_strrstr(lastpart, "/")){
		tmp = g_strsplit(lastpart, "/", 2);

		if(!g_ascii_string_to_unsigned(tmp[0], 10, 0, 255, NULL, NULL)){
			// the last part of the IP
			success = FALSE;
		}

		if(!g_ascii_string_to_unsigned(tmp[1], 10, 0, 32, NULL, NULL)){
			// the subnet portion
			success = FALSE;
		}

		g_strfreev(tmp);
	}
	else if(g_strrstr(lastpart, ":")){
		tmp = g_strsplit(lastpart, ":", 2);

		if(!g_ascii_string_to_unsigned(tmp[0], 10, 0, 255, NULL, NULL)){
			// the last part of the IP
			success = FALSE;
		}

		if(!g_ascii_string_to_unsigned(tmp[1], 10, 0, 65535, NULL, NULL)){
			// the port
			success = FALSE;
		}

		g_strfreev(tmp);
	}
	else{
		// we have neither a port nor a subnet suffix, but it's not a number either
		success = FALSE;
	}

ip4end:
	g_strfreev(parts);
	return success;
}

// check if the given string looks like an IPv6 address
// that is, several segments of up to 4 hexadecimal digits
// separated by colons, possibly followed by a slash and a subnet (0 - 128)
//
// if there are several zeroes in adjacent segments,
// those segments may be omitted
gboolean
is_ip6(char *addr)
{
	gchar **parts;
	gchar **tmp;
	gchar *lastpart;
	int len = 0;
	int i = 0;
	int num_empty = 0;
	int num_colons = 0;
	gboolean success = TRUE;

	if(!addr){
		return FALSE;
	}
	else if(!g_strrstr(addr, ":")){
		return FALSE;
	}

	while(addr && addr[i]){
		if(addr[i] == ':'){
			num_colons++;
		}
		i++;
	}
	if(num_colons < 2){
		// an IPv6 has to contain at least two colons
		return FALSE;
	}

	parts = g_strsplit(addr, ":", 0);
	while(parts && parts[len]){
		len++;
	}

	num_empty = 0;
	for(i = 0; i < (len-1); i++){
		if((i == 0) && (!g_strcmp0("", parts[i]))){
			// the beginning may be empty (e.g. in "::1")
			continue;
		}

		if(!g_strcmp0("", parts[i]) && (num_empty < 1)){
			// there may be one "skipped" part in the IP6
			num_empty++;
		}
		else if(!g_ascii_string_to_unsigned(parts[i], 16, 0, 65536, NULL, NULL)){
			// the rest of the parts have to be numerals between 0 and 16^4 in hex
			success = FALSE;
			goto ip6end;
		}
	}

	lastpart = parts[len-1];
	if(g_strrstr(lastpart, "/")){
		// we have a subnet portion
		tmp = g_strsplit(lastpart, "/", 2);

		if(g_strcmp0("", tmp[0]) && !g_ascii_string_to_unsigned(tmp[0], 16, 0, 65536, NULL, NULL)){
			success = FALSE;
		}
		else if(!g_ascii_string_to_unsigned(tmp[1], 10, 0, 128, NULL, NULL)){
			success = FALSE;
		}

		g_strfreev(tmp);
	}
	else{
		// there is only a number, or an empty string (e.g. in the case of "::")
		if(g_strcmp0("", lastpart) && !g_ascii_string_to_unsigned(lastpart, 16, 0, 65536, NULL, NULL)){
			success = FALSE;
		}
	}

ip6end:
	g_strfreev(parts);
	return success;
}

// check if the address looks like a valid FQDN
gboolean is_fqdn(char *addr)
{
	int idx = 0;
	int idx2 = 0;
	int dots = 0;
	gchar **parts;
	gchar **tmp;
	gchar *lastpart;
	gboolean success = TRUE;
	gboolean contains_alpha = FALSE;

	if(!addr){
		return FALSE;
	}

	while(addr && addr[idx]){
		if(addr[idx] == '.'){
			dots++;
		}
		idx++;
	}

	parts = g_strsplit_set(addr, ".", 0);
	lastpart = parts[dots];

	// iterate over all parts of the name
	for(idx = 0; idx <= dots; idx++){

		// if the part is empty
		if(is_empty(parts[idx])){
			success = FALSE;
			goto fqdn_end;
		}

		idx2 = 0;
		while(parts[idx] && parts[idx][idx2]){
			char c = parts[idx][idx2];

			// we have arrived at the last part and found the beginning of the port
			if((idx == dots) && (c == ':')){
				break;
			}

			if(!g_ascii_isalnum(c) && (c != '-')){
				// if there's a character other than something alphanumeric or a hyphen,
				// reject it
				// TODO: cover more than just ASCII, check length, etc.
				success = FALSE;
				goto fqdn_end;
			}

			if(g_ascii_isalpha(c)){
				contains_alpha = TRUE;
			}

			idx2++;
		}

		
	}
	// names consisting of only numbers are not legitimate
	if(!contains_alpha){
		success = FALSE;
		goto fqdn_end;
	}

	// might have a port suffix after a colon (e.g. tuwien.ac.at:8080)
	if(g_strrstr(lastpart, ":")){
		tmp = g_strsplit(lastpart, ":", 2);

		// the last part has been checked in the loop above, so we only need
		// to check the port
		if(!g_ascii_string_to_unsigned(tmp[1], 10, 0, 65535, NULL, NULL)){
			success = FALSE;
		}

		g_strfreev(tmp);
	}

fqdn_end:
	g_strfreev(parts);
	return success;
}

gboolean is_base64(char *str)
{
	char *ptr = str;
	int padding = 0;

	// Base64 only allows for alphanumeric characters along with
	// '+', '/' (and '=' as trailing padding)
	for(; ptr && *ptr; ptr++){
		if(*ptr == '='){
			padding++;
		}

		if(padding <= 0){
			if(!g_ascii_isalnum(*ptr) &&
				(*ptr != '+') &&
				(*ptr != '/')){

				return FALSE;
			}
		}else{
			if(*ptr != '='){
				return FALSE;
			}
		}
	}

	// if we have more than 3x '=', there's too much padding
	if(padding > 3){
		return FALSE;
	}

	return TRUE;
}
