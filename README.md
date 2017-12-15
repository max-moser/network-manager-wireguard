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