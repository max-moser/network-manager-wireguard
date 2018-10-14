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

#include "nm-wireguard-editor.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>

#include "utils.h"

/*****************************************************************************/

static void wireguard_editor_plugin_widget_interface_init (NMVpnEditorInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (WireguardEditor, wireguard_editor_plugin_widget, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR,
                                               wireguard_editor_plugin_widget_interface_init))

#define WIREGUARD_EDITOR_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), WIREGUARD_TYPE_EDITOR, WireguardEditorPrivate))

typedef struct {
	GtkBuilder *builder;
	GtkWidget *widget;
	gboolean new_connection;
} WireguardEditorPrivate;

/*****************************************************************************/
// functions for checking the contents of the input fields in the GUI

static gboolean
check_interface_ip4_entry(const char *str)
{
	return is_ip4((char *)str);
}

static gboolean
check_interface_ip6_entry(const char *str)
{
	return is_ip6((char *)str);
}

static gboolean
check_interface_dns_entry(const char *str)
{
	if(is_empty(str)){
		return TRUE;
	}
	else if(is_ip4((char *)str)){
		return TRUE;
	}
	else if(is_ip6((char *)str)){
		return TRUE;
	}

	return FALSE;
}

static gboolean
check_interface_mtu_entry(const char *str)
{
	if(is_empty(str)){
		return TRUE;
	}
	else if(!g_ascii_string_to_unsigned(str, 10, 0, 1500, NULL, NULL)){
		return FALSE;
	}

	return TRUE;
}

static gboolean
check_peer_persistent_keep_alive_entry(const char *str)
{
	if(is_empty(str)){
		return TRUE;
	}
	else if(!g_ascii_string_to_unsigned(str, 10, 0, 450, NULL, NULL)){
		return FALSE;
	}

	return TRUE;
}

static gboolean
check_peer_preshared_key(const char *str)
{
	if(is_empty(str)){
		return TRUE;
	}

	// WireGuard has Base64-encoded PSKs of length 44
	if(strlen(str) != 44){
		return FALSE;
	}

	return is_base64((char *)str);
}

static gboolean
check_interface_private_key(const char *str)
{
	return check_peer_preshared_key(str);
}

static gboolean
check_peer_public_key(const char *str){
	return check_peer_preshared_key(str);
}

static gboolean
check_interface_listen_port(const char *str)
{
	// Listen port is not a required field according to man wg
	if(is_empty(str)){
		return TRUE;
	}

	if(!g_ascii_string_to_unsigned(str, 10, 0, 65535, NULL, NULL)){
		return FALSE;
	}

	return TRUE;
}

static gboolean
check_peer_allowed_ips(const char *str)
{
	gchar **ips;
	int idx = 0;
	gboolean success = TRUE;

	ips = g_strsplit_set(str, ", \t", 0);

	while(ips && ips[idx]){

		if(is_empty(ips[idx])){
			idx++;
			continue;
		}

		// there should not be any trailing commas, etc. anymore
		// -> if any of the items is not a valid IPv4 or IPv6 address: error!
		if(!is_ip4(ips[idx]) && !is_ip6(ips[idx])){
			success = FALSE;
			break;
		}
		idx++;
	}
	
	g_strfreev(ips);
	return success;
}

static gboolean
check_peer_endpoint(const char *str)
{
	return is_ip4((char *)str) || is_ip6((char *)str) || is_fqdn((char *)str);
}

// used in 'check()', matches the functions above
typedef gboolean (*CheckFunc)(const char *str);

// helper function to reduce boilerplate code in 'check_validity()'
static gboolean
check (WireguardEditorPrivate *priv,
		char *widget_name,
		CheckFunc chk,
		const char *key,
		gboolean set_error,
		GError **error)
{
	const char *str;
	GtkWidget *widget;
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, widget_name));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && chk(str))
		gtk_style_context_remove_class (gtk_widget_get_style_context (widget), "error");
	else {
		gtk_style_context_add_class (gtk_widget_get_style_context (widget), "error");
		// only set the error if it's NULL
		if(error == NULL && set_error){
			g_set_error (error,
						NMV_EDITOR_PLUGIN_ERROR,
						NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
						"%s",
						key);
		}
		return FALSE;
	}

	return TRUE;
}

// add or remove the "error" class from the specified input field
static void
set_error_class(WireguardEditorPrivate *priv, char *widget_name, gboolean error)
{
	GtkWidget *widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, widget_name));
	if(error){
		gtk_style_context_add_class (gtk_widget_get_style_context (widget), "error");
	}
	else{
		gtk_style_context_remove_class (gtk_widget_get_style_context (widget), "error");
	}
}

// check if the specified input field contains any user input
static gboolean
is_filled_out(WireguardEditorPrivate *priv, char *widget_name)
{
	const char *str;
	GtkWidget *widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, widget_name));
	str = gtk_entry_get_text(GTK_ENTRY (widget));

	return !is_empty(str);
}

// check validity of the input fields in the GUI
// if there is an error in one or more of the input fields, mark the corresponding
// input fields with the "error" class
static gboolean
check_validity (WireguardEditor *self, GError **error)
{
	WireguardEditorPrivate *priv = WIREGUARD_EDITOR_GET_PRIVATE (self);
	gboolean success = TRUE;
	gboolean ip4_ok = TRUE;
	gboolean ip6_ok = TRUE;

	// check the various input fields for errors
	if(!check(priv, "interface_ip4_entry", check_interface_ip4_entry, NM_WG_KEY_ADDR_IP4, FALSE, error)){
		ip4_ok = FALSE;
	}
	if(!check(priv, "interface_ip6_entry", check_interface_ip6_entry, NM_WG_KEY_ADDR_IP6, FALSE, error)){
		ip6_ok = FALSE;
	}
	if(!check(priv, "interface_private_key_entry", check_interface_private_key, NM_WG_KEY_PRIVATE_KEY, TRUE, error)){
		success = FALSE;
	}
	if(!check(priv, "interface_port_entry", check_interface_listen_port, NM_WG_KEY_LISTEN_PORT, TRUE, error)){
		success = FALSE;
	}
	if(!check(priv, "interface_dns_entry", check_interface_dns_entry, NM_WG_KEY_DNS, TRUE, error)){
		success = FALSE;
	}
	if(!check(priv, "interface_mtu_entry", check_interface_mtu_entry, NM_WG_KEY_MTU, TRUE, error)){
		success = FALSE;
	}
	if(!check(priv, "peer_public_key_entry", check_peer_public_key, NM_WG_KEY_PUBLIC_KEY, TRUE, error)){
		success = FALSE;
	}
	if(!check(priv, "peer_allowed_ips_entry", check_peer_allowed_ips, NM_WG_KEY_ALLOWED_IPS, TRUE, error)){
		success = FALSE;
	}
	if(!check(priv, "peer_endpoint_entry", check_peer_endpoint, NM_WG_KEY_ENDPOINT, TRUE, error)){
		success = FALSE;
	}
	if(!check(priv, "peer_psk_entry", check_peer_preshared_key, NM_WG_KEY_PRESHARED_KEY, TRUE, error)){
		success = FALSE;
	}
        if(!check(priv, "peer_persistent_keep_alive_entry", check_peer_persistent_keep_alive_entry, NM_WG_KEY_PERSISTENT_KEEP_ALIVE, TRUE, error)){
		success = FALSE;
	}
	// pre-up, post-up, pre-down, post-down are scripts and don't get validated

	if(ip4_ok && ip6_ok){
		// IP4 and IP6 are both set: OK
		set_error_class(priv, "interface_ip4_entry", FALSE);
		set_error_class(priv, "interface_ip6_entry", FALSE);
	}
	else if(ip4_ok){
		if(is_filled_out(priv, "interface_ip6_entry")){
			// IP6 is filled out but not ok: NOK
			success = FALSE;
			g_set_error (error,
						NMV_EDITOR_PLUGIN_ERROR,
						NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
						NM_WG_KEY_ADDR_IP6);
		}
		else{
			// IP6 is not filled out: OK
			set_error_class(priv, "interface_ip4_entry", FALSE);
			set_error_class(priv, "interface_ip6_entry", FALSE);
		}
	}
	else if(ip6_ok){
		if(is_filled_out(priv, "interface_ip4_entry")){
			// IP4 is filled out but not ok: NOK
			success = FALSE;
			g_set_error (error,
						NMV_EDITOR_PLUGIN_ERROR,
						NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
						NM_WG_KEY_ADDR_IP4);
		}
		else{
			// IP4 is not filled out: OK
			set_error_class(priv, "interface_ip4_entry", FALSE);
			set_error_class(priv, "interface_ip6_entry", FALSE);
		}
	}

	return success;
}

// callback when input has changed
static void
stuff_changed_cb (GtkWidget *widget, gpointer user_data)
{
	g_signal_emit_by_name (WIREGUARD_EDITOR (user_data), "changed");
}

// set up the GUI: fill the contents of the input fields with the stuff contained
// in our NMConnection
static gboolean
init_editor_plugin (WireguardEditor *self, NMConnection *connection, GError **error)
{
	WireguardEditorPrivate *priv = WIREGUARD_EDITOR_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	GtkWidget *widget;
	const char *value;

	s_vpn = nm_connection_get_setting_vpn (connection);

	// Local IPv4 address
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_ip4_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_WG_KEY_ADDR_IP4);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	// Local IPv6 address
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_ip6_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_WG_KEY_ADDR_IP6);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	// DNS
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_dns_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_WG_KEY_DNS);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	// Interface MTU
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_mtu_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_WG_KEY_MTU);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	// Interface Private Key
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_private_key_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_WG_KEY_PRIVATE_KEY);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	// Interface Listening Port
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_port_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_WG_KEY_LISTEN_PORT);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	// Interface Pre Up
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_pre_up_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_WG_KEY_PRE_UP);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	// Interface Post Up
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_post_up_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_WG_KEY_POST_UP);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	// Interface Pre Down
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_pre_down_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_WG_KEY_PRE_DOWN);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	// Interface Post Down
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_post_down_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_WG_KEY_POST_DOWN);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	// Interface Preshared Key
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "peer_psk_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_WG_KEY_PRESHARED_KEY);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

        // Peer Persistent Keep Alive
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "peer_persistent_keep_alive_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_WG_KEY_PERSISTENT_KEEP_ALIVE);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);
	
	// Peer Public Key
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "peer_public_key_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_WG_KEY_PUBLIC_KEY);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	// Peer Allowed IPs
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "peer_allowed_ips_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_WG_KEY_ALLOWED_IPS);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	// Peer Endpoint
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "peer_endpoint_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_WG_KEY_ENDPOINT);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	return TRUE;
}

// get the active widget (config GUI)
static GObject *
get_widget (NMVpnEditor *iface)
{
	WireguardEditor *self = WIREGUARD_EDITOR (iface);
	WireguardEditorPrivate *priv = WIREGUARD_EDITOR_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
}

// check if the user's inputs are valid and if so, update the NMConnection's
// NMSettingVpn data items (gets called everytime something changes, afaik)
static gboolean
update_connection (NMVpnEditor *iface,
                   NMConnection *connection,
                   GError **error)
{
	WireguardEditor *self = WIREGUARD_EDITOR (iface);
	WireguardEditorPrivate *priv = WIREGUARD_EDITOR_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	GtkWidget *widget;
	const char *str;
	gboolean valid = FALSE;

	// validity check is done before anything else
	if (!check_validity (self, error)){
		return FALSE;
	}

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_VPN_SERVICE_TYPE_WIREGUARD, NULL);

	// local ip4
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_ip4_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && str[0]){
		nm_setting_vpn_add_data_item (s_vpn, NM_WG_KEY_ADDR_IP4, str);
	}

	// local ip6
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_ip6_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && str[0]){
		nm_setting_vpn_add_data_item (s_vpn, NM_WG_KEY_ADDR_IP6, str);
	}

	// private key
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_private_key_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && str[0]){
		nm_setting_vpn_add_data_item (s_vpn, NM_WG_KEY_PRIVATE_KEY, str);
	}

	// dns
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_dns_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && str[0]){
		nm_setting_vpn_add_data_item (s_vpn, NM_WG_KEY_DNS, str);
	}

	// mtu
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_mtu_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && str[0]){
		nm_setting_vpn_add_data_item (s_vpn, NM_WG_KEY_MTU, str);
	}

	// listen port
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_port_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && str[0]){
		nm_setting_vpn_add_data_item (s_vpn, NM_WG_KEY_LISTEN_PORT, str);
	}

	// pre up script
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_pre_up_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && str[0]){
		nm_setting_vpn_add_data_item (s_vpn, NM_WG_KEY_PRE_UP, str);
	}

	// post up script
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_post_up_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && str[0]){
		nm_setting_vpn_add_data_item (s_vpn, NM_WG_KEY_POST_UP, str);
	}

	// pre up script
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_pre_down_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && str[0]){
		nm_setting_vpn_add_data_item (s_vpn, NM_WG_KEY_PRE_DOWN, str);
	}

	// post down script
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_post_down_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && str[0]){
		nm_setting_vpn_add_data_item (s_vpn, NM_WG_KEY_POST_DOWN, str);
	}

	// preshared key
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "peer_psk_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && str[0]){
		nm_setting_vpn_add_data_item (s_vpn, NM_WG_KEY_PRESHARED_KEY, str);
	}

	// peer public key
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "peer_public_key_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && str[0]){
		nm_setting_vpn_add_data_item (s_vpn, NM_WG_KEY_PUBLIC_KEY, str);
	}

	// allowed IPs
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "peer_allowed_ips_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && str[0]){
		nm_setting_vpn_add_data_item (s_vpn, NM_WG_KEY_ALLOWED_IPS, str);
	}

	// endpoint
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "peer_endpoint_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && str[0]){
		nm_setting_vpn_add_data_item (s_vpn, NM_WG_KEY_ENDPOINT, str);
	}
        
        // persistent keep alive
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "peer_persistent_keep_alive_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && str[0]){
		nm_setting_vpn_add_data_item (s_vpn, NM_WG_KEY_PERSISTENT_KEEP_ALIVE, str);
	}

	nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	valid = TRUE;

	return valid;
}

// function to determine if the connection is new, according to its data items
static void
is_new_func (const char *key, const char *value, gpointer user_data)
{
	gboolean *is_new = user_data;

	/* If there are any VPN data items the connection isn't new */
	*is_new = FALSE;
}

/*****************************************************************************/

static void
wireguard_editor_plugin_widget_init (WireguardEditor *plugin)
{
}

NMVpnEditor *
wireguard_editor_new (NMConnection *connection, GError **error)
{
	NMVpnEditor *object;
	WireguardEditorPrivate *priv;
	gboolean new = TRUE;
	NMSettingVpn *s_vpn;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	object = g_object_new (WIREGUARD_TYPE_EDITOR, NULL);
	if (!object) {
		g_set_error_literal (error, NMV_EDITOR_PLUGIN_ERROR, 0, "Could not create wireguard object");
		return NULL;
	}

	priv = WIREGUARD_EDITOR_GET_PRIVATE (object);

	priv->builder = gtk_builder_new ();

	gtk_builder_set_translation_domain (priv->builder, GETTEXT_PACKAGE);

	// create the GUI from our .ui file
	// note: the resource is described in gresource.xml and gets compiled to resources.c
	if (!gtk_builder_add_from_resource (priv->builder, "/org/freedesktop/network-manager-wireguard/nm-wireguard-dialog.ui", error)) {
		g_object_unref (object);
		g_return_val_if_reached (NULL);
	}

	priv->widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "wg-vbox"));
	if (!priv->widget) {
		g_set_error_literal (error, NMV_EDITOR_PLUGIN_ERROR, 0, _("could not load UI widget"));
		g_object_unref (object);
		g_return_val_if_reached (NULL);
	}
	g_object_ref_sink (priv->widget);

	s_vpn = nm_connection_get_setting_vpn (connection);
	// if there is at least one item to iterate over, the connection can't be new
	if (s_vpn)
		nm_setting_vpn_foreach_data_item (s_vpn, is_new_func, &new);
	priv->new_connection = new;

	if (!init_editor_plugin (WIREGUARD_EDITOR (object), connection, error)) {
		g_object_unref (object);
		return NULL;
	}

	return object;
}

static void
dispose (GObject *object)
{
	WireguardEditor *plugin = WIREGUARD_EDITOR (object);
	WireguardEditorPrivate *priv = WIREGUARD_EDITOR_GET_PRIVATE (plugin);

	g_clear_object (&priv->widget);

	g_clear_object (&priv->builder);

	G_OBJECT_CLASS (wireguard_editor_plugin_widget_parent_class)->dispose (object);
}

static void
wireguard_editor_plugin_widget_interface_init (NMVpnEditorInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
}

static void
wireguard_editor_plugin_widget_class_init (WireguardEditorClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (WireguardEditorPrivate));

	object_class->dispose = dispose;
}

/*****************************************************************************/

#ifndef NM_VPN_OLD

#include "nm-wireguard-editor-plugin.h"

G_MODULE_EXPORT NMVpnEditor *
nm_vpn_editor_factory_wireguard (NMVpnEditorPlugin *editor_plugin,
                               NMConnection *connection,
                               GError **error)
{
	g_return_val_if_fail (!error || !*error, NULL);

	return wireguard_editor_new (connection, error);
}
#endif

