AUTOMAKE_OPTIONS = foreign subdir-objects

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-more-warnings=yes

libexec_PROGRAMS =

noinst_LTLIBRARIES =

EXTRA_DIST =

CLEANFILES =

check_programs =

noinst_PROGRAMS =

SUBDIRS = \
	. \
	po

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES =

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-openvpn-service.conf

nmvpnservicedir = $(NM_VPN_SERVICE_DIR)
nmvpnservice_DATA = nm-openvpn-service.name

uidir = $(datadir)/gnome-vpn-properties/openvpn
ui_DATA =

###############################################################################

shared_sources = \
	shared/nm-utils/nm-shared-utils.c \
	shared/utils.c

###############################################################################

src_cppflags = \
	-DBINDIR=\"$(bindir)\" \
	-DPREFIX=\""$(prefix)"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DLIBDIR=\""$(libdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DLOCALSTATEDIR=\""$(localstatedir)"\" \
	-DDATADIR=\"$(datadir)\" \
	-DNM_OPENVPN_LOCALEDIR=\"$(datadir)/locale\" \
	-DG_LOG_DOMAIN=\"nm-openvpn\" \
	-I$(srcdir)/shared \
	$(GLIB_CFLAGS) \
	$(LIBNM_CFLAGS)

noinst_LTLIBRARIES += src/libnm-utils.la

src_libnm_utils_la_SOURCES = $(shared_sources)
src_libnm_utils_la_CPPFLAGS = $(src_cppflags)
src_libnm_utils_la_LIBADD = \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS)

libexec_PROGRAMS += src/nm-openvpn-service

src_nm_openvpn_service_CPPFLAGS = $(src_cppflags)
src_nm_openvpn_service_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver"
src_nm_openvpn_service_LDADD = \
	src/libnm-utils.la \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS)
EXTRA_src_nm_openvpn_service_DEPENDENCIES = \
	linker-script-binary.ver

libexec_PROGRAMS += src/nm-openvpn-service-openvpn-helper

src_nm_openvpn_service_openvpn_helper_CPPFLAGS = $(src_cppflags)
src_nm_openvpn_service_openvpn_helper_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver"
src_nm_openvpn_service_openvpn_helper_LDADD = \
	src/libnm-utils.la \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS)
EXTRA_src_nm_openvpn_service_openvpn_helper_DEPENDENCIES = \
	linker-script-binary.ver

###############################################################################

properties/resources.h: properties/gresource.xml
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/properties --generate-header --internal

properties/resources.c: properties/gresource.xml $(shell $(GLIB_COMPILE_RESOURCES) --sourcedir=$(srcdir)/properties --generate-dependencies $(srcdir)/properties/gresource.xml)
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/properties --generate-source --internal

CLEANFILES += \
	properties/resources.c \
	properties/resources.h

EXTRA_DIST += \
	properties/gresource.xml

plugin_sources = \
	properties/nm-openvpn-editor-plugin.c \
	properties/nm-openvpn-editor-plugin.h \
	properties/import-export.c \
	properties/import-export.h

editor_sources = \
	properties/resources.c \
	properties/resources.h \
	properties/nm-openvpn-editor.c \
	properties/nm-openvpn-editor.h \
	properties/auth-helpers.c \
	properties/auth-helpers.h

properties_cppflags = \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DLOCALEDIR=\"$(datadir)/locale\" \
	-I$(srcdir)/shared \
	$(GLIB_CFLAGS)

###############################################################################

noinst_LTLIBRARIES += properties/libnm-vpn-plugin-openvpn-utils.la

properties_libnm_vpn_plugin_openvpn_utils_la_SOURCES = \
	$(shared_sources)

properties_libnm_vpn_plugin_openvpn_utils_la_CPPFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_BASE \
	-DNM_PLUGIN_DIR=\"$(NM_PLUGIN_DIR)\" \
	$(properties_cppflags) \
	$(LIBNM_CFLAGS)

properties_libnm_vpn_plugin_openvpn_utils_la_LIBADD = \
	$(LIBNM_LIBS) \
	$(DL_LIBS)

noinst_LTLIBRARIES += properties/libnm-vpn-plugin-openvpn-core.la

properties_libnm_vpn_plugin_openvpn_core_la_SOURCES = \
	shared/nm-utils/nm-vpn-plugin-utils.c \
	shared/nm-utils/nm-vpn-plugin-utils.h \
	shared/nm-utils/nm-vpn-plugin-macros.h \
	$(plugin_sources)

properties_libnm_vpn_plugin_openvpn_core_la_CPPFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_BASE \
	-DNM_PLUGIN_DIR=\"$(NM_PLUGIN_DIR)\" \
	$(properties_cppflags) \
	$(LIBNM_CFLAGS)

properties_libnm_vpn_plugin_openvpn_core_la_LIBADD = \
	properties/libnm-vpn-plugin-openvpn-utils.la \
	$(LIBNM_LIBS) \
	$(DL_LIBS)

plugin_LTLIBRARIES += properties/libnm-vpn-plugin-openvpn.la

properties_libnm_vpn_plugin_openvpn_la_SOURCES =
properties_libnm_vpn_plugin_openvpn_la_LIBADD = \
	properties/libnm-vpn-plugin-openvpn-core.la
properties_libnm_vpn_plugin_openvpn_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script=$(srcdir)/properties/libnm-vpn-plugin-openvpn.ver

###############################################################################

if WITH_GNOME
plugin_LTLIBRARIES += properties/libnm-vpn-plugin-openvpn-editor.la
endif

properties_libnm_vpn_plugin_openvpn_editor_la_SOURCES = \
	$(editor_sources)

properties_libnm_vpn_plugin_openvpn_editor_la_CPPFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR \
	$(properties_cppflags) \
	$(GTK_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS)

properties_libnm_vpn_plugin_openvpn_editor_la_LIBADD = \
	properties/libnm-vpn-plugin-openvpn-utils.la \
	$(GLIB_LIBS) \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS)

properties_libnm_vpn_plugin_openvpn_editor_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script=$(srcdir)/properties/libnm-vpn-plugin-openvpn-editor.ver

###############################################################################

if WITH_LIBNM_GLIB
noinst_LTLIBRARIES += properties/libnm-openvpn-properties-core.la
endif

properties_libnm_openvpn_properties_core_la_SOURCES = \
	$(shared_sources) \
	$(plugin_sources) \
	$(editor_sources)

properties_libnm_openvpn_properties_core_la_CPPFLAGS = \
	-DNM_VPN_OLD \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
	$(properties_cppflags) \
	$(GTK_CFLAGS) \
	$(LIBNM_GLIB_CFLAGS) \
	$(LIBNM_GTK_CFLAGS)

properties_libnm_openvpn_properties_core_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GTK_LIBS) \
	$(LIBNM_GLIB_LIBS) \
	$(LIBNM_GTK_LIBS)


if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += properties/libnm-openvpn-properties.la
endif

properties_libnm_openvpn_properties_la_SOURCES =
properties_libnm_openvpn_properties_la_LIBADD = \
	properties/libnm-openvpn-properties-core.la
properties_libnm_openvpn_properties_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script=$(srcdir)/properties/libnm-openvpn-properties.ver

EXTRA_DIST += \
	properties/libnm-vpn-plugin-openvpn.ver \
	properties/libnm-vpn-plugin-openvpn-editor.ver \
	properties/libnm-openvpn-properties.ver \
	properties/nm-openvpn-dialog.ui

###############################################################################

properties_tests_cppflags = \
	-DTEST_SRCDIR="\"$(abs_srcdir)/properties/tests\"" \
	-DTEST_BUILDDIR="\"$(abs_builddir)/properties/tests\"" \
	-I$(srcdir)/shared \
	-I$(srcdir)/properties \
	$(GLIB_CFLAGS)


check_programs += properties/tests/test-import-export

properties_tests_test_import_export_SOURCES = \
	properties/tests/test-import-export.c

properties_tests_test_import_export_CPPFLAGS = \
	$(properties_tests_cppflags) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS)

properties_tests_test_import_export_LDADD = \
	properties/libnm-vpn-plugin-openvpn-core.la \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS)


if WITH_LIBNM_GLIB
check_programs += properties/tests/test-import-export-glib
endif

properties_tests_test_import_export_glib_SOURCES = \
	properties/tests/test-import-export.c

properties_tests_test_import_export_glib_CPPFLAGS = \
	-DNM_VPN_OLD \
	$(properties_tests_cppflags) \
	$(GTK_CFLAGS) \
	$(LIBNM_GLIB_CFLAGS) \
	$(LIBNM_GTK_CFLAGS)

properties_tests_test_import_export_glib_LDADD = \
	properties/libnm-openvpn-properties-core.la \
	$(GLIB_LIBS) \
	$(GTK_LIBS) \
	$(LIBNM_GLIB_LIBS) \
	$(LIBNM_GTK_LIBS)


EXTRA_DIST += \
	properties/tests/conf/iso885915.ovpn \
	properties/tests/conf/mtu-disc.ovpn \
	properties/tests/conf/password.conf \
	properties/tests/conf/pkcs12.ovpn \
	properties/tests/conf/port.ovpn \
	properties/tests/conf/rport.ovpn \
	properties/tests/conf/static.key \
	properties/tests/conf/static.ovpn \
	properties/tests/conf/static2.ovpn \
	properties/tests/conf/tls.ovpn \
	properties/tests/conf/tls2.ovpn \
	properties/tests/conf/tun-opts.conf \
	properties/tests/conf/proxy-http.ovpn \
	properties/tests/conf/httpauthfile \
	properties/tests/conf/proxy-socks.ovpn \
	properties/tests/conf/proxy-http-with-auth.ovpn \
	properties/tests/conf/keysize.ovpn \
	properties/tests/conf/device.ovpn \
	properties/tests/conf/device-notype.ovpn \
	properties/tests/conf/keepalive.ovpn \
	properties/tests/conf/ping-with-exit.ovpn \
	properties/tests/conf/ping-with-restart.ovpn \
	properties/tests/conf/route.ovpn \
	properties/tests/conf/tls-inline.ovpn \
	properties/tests/conf/tls-inline-ca.pem \
	properties/tests/conf/tls-inline-cert.pem \
	properties/tests/conf/tls-inline-key.pem \
	properties/tests/conf/tls-inline-ta.pem

###############################################################################

if WITH_GNOME
libexec_PROGRAMS += auth-dialog/nm-openvpn-auth-dialog
endif

auth_dialog_nm_openvpn_auth_dialog_SOURCES = \
	$(shared_sources) \
	auth-dialog/main.c
auth_dialog_nm_openvpn_auth_dialog_CPPFLAGS = \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DGNOMELOCALEDIR=\"$(datadir)/locale\" \
	-I$(srcdir)/shared \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS) \
	$(LIBSECRET_CFLAGS)
auth_dialog_nm_openvpn_auth_dialog_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver"
auth_dialog_nm_openvpn_auth_dialog_LDADD = \
	$(GLIB_LIBS) \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS) \
	$(LIBSECRET_LIBS)
EXTRA_auth_dialog_nm_openvpn_auth_dialog_DEPENDENCIES = \
	linker-script-binary.ver

###############################################################################

if WITH_LIBNM_GLIB
# Install a file with full path to plugins for an old gnome-shell
# https://bugzilla.gnome.org/show_bug.cgi?id=693590
install-data-hook:
	mkdir -p $(DESTDIR)$(sysconfdir)/NetworkManager/VPN
	sed -e "1s|^|# This file is obsoleted by a file in $(NM_VPN_SERVICE_DIR)\n\n|" \
	    -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]|@NM_PLUGIN_DIR@|g' \
	    <$(srcdir)/nm-openvpn-service.name.in \
	    >$(DESTDIR)$(sysconfdir)/NetworkManager/VPN/nm-openvpn-service.name

uninstall-hook:
	 rm -f $(DESTDIR)$(sysconfdir)/NetworkManager/VPN/nm-openvpn-service.name
endif

appdatadir = $(datadir)/appdata
appdata_files = $(appdata_in_files:.xml.in=.xml)
if WITH_GNOME
appdata_DATA = $(appdata_files)
endif
appdata_in_files = appdata/network-manager-openvpn.metainfo.xml.in
@INTLTOOL_XML_RULE@

nm-openvpn-service.name: $(srcdir)/nm-openvpn-service.name.in
	$(AM_V_GEN) sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]/|@NM_PLUGIN_DIR_NAME_FILE@|g' \
	    $^ >$@

# we always build the tests during regular build.
noinst_PROGRAMS += $(check_programs)

TESTS = $(check_programs)

EXTRA_DIST += \
	linker-script-binary.ver \
	nm-openvpn-service.name.in \
	$(dbusservice_DATA) \
	$(appdata_in_files) \
	$(appdata_files) \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in \
	\
	shared/README \
	shared/nm-utils/gsystem-local-alloc.h \
	shared/nm-utils/nm-glib.h \
	shared/nm-utils/nm-macros-internal.h \
	shared/nm-utils/nm-shared-utils.c \
	shared/nm-utils/nm-shared-utils.h \
	shared/nm-utils/nm-test-utils.h \
	shared/nm-default.h \
	shared/nm-service-defines.h \
	shared/utils.c \
	shared/utils.h \
	$(NULL)

CLEANFILES += \
	$(nmvpnservice_DATA) \
	$(appdata_files)

DISTCLEANFILES = \
	intltool-extract \
	intltool-merge \
	intltool-update

ACLOCAL_AMFLAGS = -I m4
