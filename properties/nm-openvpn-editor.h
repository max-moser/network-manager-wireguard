/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * nm-openvpn-editor.h : GNOME UI dialogs for configuring openvpn VPN connections
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

#ifndef __NM_OPENVPN_EDITOR_H__
#define __NM_OPENVPN_EDITOR_H__

#define OPENVPN_TYPE_EDITOR            (openvpn_editor_plugin_widget_get_type ())
#define OPENVPN_EDITOR(obj)                      (G_TYPE_CHECK_INSTANCE_CAST ((obj), OPENVPN_TYPE_EDITOR, OpenvpnEditor))
#define OPENVPN_EDITOR_CLASS(klass)              (G_TYPE_CHECK_CLASS_CAST ((klass), OPENVPN_TYPE_EDITOR, OpenvpnEditorClass))
#define OPENVPN_IS_EDITOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), OPENVPN_TYPE_EDITOR))
#define OPENVPN_IS_EDITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), OPENVPN_TYPE_EDITOR))
#define OPENVPN_EDITOR_GET_CLASS(obj)            (G_TYPE_INSTANCE_GET_CLASS ((obj), OPENVPN_TYPE_EDITOR, OpenvpnEditorClass))

typedef struct _OpenvpnEditor OpenvpnEditor;
typedef struct _OpenvpnEditorClass OpenvpnEditorClass;

struct _OpenvpnEditor {
	GObject parent;
};

struct _OpenvpnEditorClass {
	GObjectClass parent;
};

GType openvpn_editor_plugin_widget_get_type (void);

NMVpnEditor *openvpn_editor_new (NMConnection *connection, GError **error);

#endif	/* __NM_OPENVPN_EDITOR_H__ */

