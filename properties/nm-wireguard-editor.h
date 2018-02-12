/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * nm-wireguard-editor.h : GNOME UI dialogs for configuring wireguard VPN connections
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

#ifndef __NM_WIREGUARD_EDITOR_H__
#define __NM_WIREGUARD_EDITOR_H__

#define WIREGUARD_TYPE_EDITOR            (wireguard_editor_plugin_widget_get_type ())
#define WIREGUARD_EDITOR(obj)                      (G_TYPE_CHECK_INSTANCE_CAST ((obj), WIREGUARD_TYPE_EDITOR, WireguardEditor))
#define WIREGUARD_EDITOR_CLASS(klass)              (G_TYPE_CHECK_CLASS_CAST ((klass), WIREGUARD_TYPE_EDITOR, WireguardEditorClass))
#define WIREGUARD_IS_EDITOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), WIREGUARD_TYPE_EDITOR))
#define WIREGUARD_IS_EDITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), WIREGUARD_TYPE_EDITOR))
#define WIREGUARD_EDITOR_GET_CLASS(obj)            (G_TYPE_INSTANCE_GET_CLASS ((obj), WIREGUARD_TYPE_EDITOR, WireguardEditorClass))

typedef struct _WireguardEditor WireguardEditor;
typedef struct _WireguardEditorClass WireguardEditorClass;

struct _WireguardEditor {
	GObject parent;
};

struct _WireguardEditorClass {
	GObjectClass parent;
};

GType wireguard_editor_plugin_widget_get_type (void);

NMVpnEditor *wireguard_editor_new (NMConnection *connection, GError **error);

#endif	/* __NM_WIREGUARD_EDITOR_H__ */

