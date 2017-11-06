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

#ifndef __NM_OPENVPN_EDITOR_PLUGIN_H__
#define __NM_OPENVPN_EDITOR_PLUGIN_H__

#define OPENVPN_TYPE_EDITOR_PLUGIN                (openvpn_editor_plugin_get_type ())
#define OPENVPN_EDITOR_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), OPENVPN_TYPE_EDITOR_PLUGIN, OpenvpnEditorPlugin))
#define OPENVPN_EDITOR_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), OPENVPN_TYPE_EDITOR_PLUGIN, OpenvpnEditorPluginClass))
#define OPENVPN_IS_EDITOR_PLUGIN(obj)             (G_TYPE_CHECK_INSTANCE_TYPE ((obj), OPENVPN_TYPE_EDITOR_PLUGIN))
#define OPENVPN_IS_EDITOR_PLUGIN_CLASS(klass)     (G_TYPE_CHECK_CLASS_TYPE ((klass), OPENVPN_TYPE_EDITOR_PLUGIN))
#define OPENVPN_EDITOR_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), OPENVPN_TYPE_EDITOR_PLUGIN, OpenvpnEditorPluginClass))

typedef struct _OpenvpnEditorPlugin OpenvpnEditorPlugin;
typedef struct _OpenvpnEditorPluginClass OpenvpnEditorPluginClass;

struct _OpenvpnEditorPlugin {
	GObject parent;
};

struct _OpenvpnEditorPluginClass {
	GObjectClass parent;
};

GType openvpn_editor_plugin_get_type (void);

typedef NMVpnEditor *(*NMVpnEditorFactory) (NMVpnEditorPlugin *editor_plugin,
                                            NMConnection *connection,
                                            GError **error);

NMVpnEditor *
nm_vpn_editor_factory_openvpn (NMVpnEditorPlugin *editor_plugin,
                               NMConnection *connection,
                               GError **error);

#endif /* __NM_OPENVPN_EDITOR_PLUGIN_H__ */

