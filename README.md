# Network-Manager VPN Plugin for Wireguard

## Compilation
* `./autogen.sh`
* `make`

## Modifying the source (Visual Studio Code)
* Open the folder in Code
* Do the compilation steps as above
* `cat Makefile | ./includes2strings.py`
* take the output of the script and put it in the appropriate section of `.vscode/c_cpp_properties.json` (for me: appended to `includePath` of configuration `Linux`)

## Execution
The following section briefly describes how to start the stuff for testing purposes

* `./src/nm-openvpn-service --bus-name org.freedesktop.NetworkManager.wireguard` to start the plugin
* `examples/dbus/dbus.py` to send Disconnect() to the plugin

## Files
The following is a list of files that I created over the course of the project and is mainly for myself to keep track of them.

* `nm-wireguard-service.conf`
* `includes2strings.py`

## Knowledge
* The wireguard plugin basically handles incoming DBUS requests for the *NM VPN Plugin Interface* (can be looked at via `examples/dbus/dbus.py`)
* `auth-dialog/nm-openvpn-auth-dialog` reads the secrets from STDIN until the string "DONE" occurs and then proceeds to handle them

NM VPN Plugin:
https://developer.gnome.org/libnm-glib/stable/libnm-glib-NMVPNPlugin.html

Settings VPN (sent via DBus on Connect(a{sa{sv}}) method):
https://developer.gnome.org/libnm/stable/NMSettingVpn.html#nm-setting-vpn-get-data-item