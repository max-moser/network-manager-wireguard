# Network-Manager VPN Plugin for WireGuard

This project is a VPN Plugin for NetworkManager that handles client-side WireGuard connections.  
It is based on the [OpenVPN Plugin](https://git.gnome.org/browse/network-manager-openvpn) and was started as a Bachelor's Thesis at [SBA Research](https://www.sba-research.org/).



## Guide


### Compilation
For compilation, the project uses autoconf and related things.
* `./autogen.sh`
* `make`


### Installation
In order to get the plugin running, its sources have to be compiled and the result has to be installed. This can be done by following these steps: 
* Compile the project
* `sudo make sysconfdir=/etc libdir=/usr/lib install` (don't worry; for uninstalling, there is the target `uninstall`)


### Execution
Once the installation is completed, the Plugin can be used per NetworkManager (usually graphically via the applet).

When a new WireGuard connection is created and configured via the NetworkManager GUI (can also be called via `nm-connection-editor`), it is the Connection Editor Plugin which is executed.
When the connection is activated, it is the service plugin that is being called.

A very basic testing suite is provided in the form of the Python script `examples/dbus/dbus.py`, which looks up the Plugin via name on D-Bus and sends it a Connect() instruction. More or less the same thing (and more) can however be achieved by just using NetworkManager after installing the package, so there should not be a need for this - except for the fact that the script is easily modifiable.


### Viewing Logs
The logs that are created by NetworkManager can be viewed with `journalctl -u NetworkManager` (at least on Arch Linux). For following new input, `journalctl` also supports the follow flag, much like `tail` (`-f`).



## Files


### Scripts
Over the course of the project, I created some files that are not required for the project itself, but rather for its development.  
Here is a brief overview over some of them:
* `includes2strings.py`: Searches the input for `-I` flags (useful for extracting the include dirs from a Makefile)
* `examples/dbus/dbus.py`: A small script that tests the availability of the Plugin and its responsiveness to D-Bus messages


### Configuration

#### D-Bus Allowance

D-Bus does not allow just anybody to own any D-Bus service name they like. Thus, it may be necessary to tell D-Bus that it is not forbidden to use the name `org.freedesktop.NetworkManager.wireguard`.  
This can be achieved by placing an appropriate file (like `nm-wireguard-service.conf`) inside the directory `/etc/dbus-1/system.d` or similar.

The following is an example for the content of such a file:
~~~~xml
<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">

<busconfig>
	<policy context="default">
		<allow own_prefix="org.freedesktop.NetworkManager.wireguard"/>
		<allow send_destination="org.freedesktop.NetworkManager.wireguard"/>
		<deny own_prefix="org.freedesktop.NetworkManager.openvpn"/>
		<deny send_destination="org.freedesktop.NetworkManager.openvpn"/>
	</policy>
</busconfig>
~~~~

#### NetworkManager Plugin Configuration

NetworkManager has to be told where the plugins live in order to be able to call them. This is done via `service.name` files, which usually reside in `/etc/NetworkManager/VPN` or `/usr/lib/NetworkManager/VPN` (e.g. `/usr/lib/NetworkManager/VPN/nm-wireguard-service.name`).

An example for the content of these files would be:
~~~~ini
# This file is obsoleted by a file in /usr/local/lib/NetworkManager/VPN

[VPN Connection]
name=wireguard
service=org.freedesktop.NetworkManager.wireguard
program=/usr/local/libexec/nm-wireguard-service
supports-multiple-connections=false

[libnm]
plugin=/usr/local/lib/NetworkManager/libnm-vpn-plugin-wireguard.so

[GNOME]
auth-dialog=/usr/local/libexec/nm-wireguard-auth-dialog
properties=/usr/local/lib/NetworkManager/libnm-wireguard-properties
supports-external-ui-mode=false
supports-hints=false
~~~~



## Knowledge


### Service (the Plugin itself)

The service is responsible for setting up a VPN connection with the supplied parameters. For this, it has to implement a [D-Bus interface](https://developer.gnome.org/NetworkManager/stable/gdbus-org.freedesktop.NetworkManager.VPN.Plugin.html) and listen to incoming requests, which will be sent by NetworkManager in due time (i.e. when the user tells NM to set up the appropriate VPN connection).  
If the binary service is not running at the time when NM wants to set up the connection, it will try to start the binary ad hoc.

In principle, this piece of software can be written in any language, but in order to make the implementation sane, there should at least exist convenient D-Bus bindings for the language. Further, there are parts of the code already implemented in C, which might make it more convenient to just stick to that.


### Auth-Dialog

The auth-dialog is responsible for figuring out missing bits of required sensitive information (such as passwords).

It reads the required secrets (and bits of data) for the VPN connection from STDIN in a key/value pair format (see below), until the string "DONE" occurs.  
If there are still secrets (i.e. passwords) that are required but not supplied (which passwords are required can be determined by looking at the supplied `hints` flags), the auth-dialog will check if the keyring contains those secrets.  
If there are still secrets missing (and user interaction is allowed per flag), a GTK dialog will be built up in order to prompt the user for passwords.

After all is said and done, the binary writes the found secrets to STDOUT (in a line-based format, as seen below) and waits for "QUIT" to be read from STDIN before exiting.

The behaviour of the binary can be modified by passing various options:
* `-u UUID`: The UUID of the VPN connection, used for looking up secrets from the keyring
* `-n NAME`: The name of the VPN connection, shown on the popup dialog
* `-s SERVICE`: Specifies the name of the VPN service, e.g. `org.freedesktop.NetworkManager.openvpn` (used to check for compatibility)
* `-i`: Allow interaction with the user (i.e. allow a GUI dialog to be created)
* `--external-ui-mode`: Give a textual description of the dialog instead of creating a GTK dialog
* `-r`: Force the creation of a dialog, even if all passwords were already found
* `-t HINT`: Give hints about what passwords are required 

Example input:
~~~~
DATA_KEY=key
DATA_VAL=value
DATA_KEY=another-key
DATA_VAL=another-value
SECRET_KEY=password
SECRET_VAL=verysecurepassword
DONE
~~~~

Example output:
~~~~
password
verysecurepassword
~~~~


### Connection Editor Plugin

The Connection Editor Plugin is responsible for providing a GUI inside NetworkManager where all relevant properties for a VPN connection can be specified. If you don't know what I'm talking about, just think about the GUI where you entered the information needed to connect to your local Wifi. That's probably pretty similar.

The Editor Plugin is also responsible for providing means of importing and exporting VPN connections from and to external files in a custom format.

NetworkManager integrates the VPN editors by looking up _shared objects_ in the above mentioned configuration file and accessing them at run-time.  
This means however that the editor plugin GUI has to be provided by a shared object, which means that the editor cannot be written in just any language.


### Storage of the Connections

Saved connections are stored in `/etc/NetworkManager/system-connections`, with owner `root:root` and access permissions `0700`.  
This guarantees that nobody can have a look at the saved system-wide connections (and their stored secrets) that isn't supposed to.

An example of such a system-connection file would be (one can see that the user-input data is stored as key-value pairs with internally used keys in the vpn section):
~~~~ini
[connection]
id=wiretest
uuid=8298d5ea-73d5-499b-9376-57409a7a2331
type=vpn
autoconnect=false
permissions=

[vpn]
local-ip4=192.168.1.2/24
local-listen-port=51820
local-private-key=CBomGS37YC4ak+J2+NPuHtmgIk6gC7yQZKHnboJd3F8=
peer-allowed-ips=192.168.1.254
peer-endpoint=8.16.32.11:51820
peer-public-key=GRk7K3A3JCaoVN1ZhFEtEvyU6+g+FdGaCtSObIYvXX0=
service-type=org.freedesktop.NetworkManager.wireguard

[vpn-secrets]
password
verysecurepassword

[ipv4]
dns-search=
method=auto

[ipv6]
addr-gen-mode=stable-privacy
dns-search=
ip6-privacy=0
method=auto
~~~~




# Resources

NM VPN Plugin:  
https://developer.gnome.org/libnm-glib/stable/libnm-glib-NMVPNPlugin.html  
https://developer.gnome.org/NetworkManager/stable/gdbus-org.freedesktop.NetworkManager.VPN.Plugin.html  

Settings VPN (sent via DBus on Connect(a{sa{sv}}) method):  
https://developer.gnome.org/libnm/stable/NMSettingVpn.html#nm-setting-vpn-get-data-item
