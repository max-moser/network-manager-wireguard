/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 *
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
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

#ifndef _AUTH_HELPERS_H_
#define _AUTH_HELPERS_H_

#include <gtk/gtk.h>

typedef void (*ChangedCallback) (GtkWidget *widget, gpointer user_data);

void tls_pw_init_auth_widget (GtkBuilder *builder,
                              NMSettingVpn *s_vpn,
                              const char *contype,
                              const char *prefix,
                              ChangedCallback changed_cb,
                              gpointer user_data);

void sk_init_auth_widget (GtkBuilder *builder,
                          NMSettingVpn *s_vpn,
                          ChangedCallback changed_cb,
                          gpointer user_data);

gboolean auth_widget_check_validity (GtkBuilder *builder, const char *contype, GError **error);

gboolean auth_widget_update_connection (GtkBuilder *builder,
                                        const char *contype,
                                        NMSettingVpn *s_vpn);

GtkFileFilter *tls_file_chooser_filter_new (gboolean pkcs_allowed);

GtkFileFilter *sk_file_chooser_filter_new (void);

GtkWidget *advanced_dialog_new (GHashTable *hash, const char *contype);

GHashTable *advanced_dialog_new_hash_from_connection (NMConnection *connection, GError **error);

GHashTable *advanced_dialog_new_hash_from_dialog (GtkWidget *dialog, GError **error);

#endif
