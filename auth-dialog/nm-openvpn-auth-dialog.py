#!/usr/bin/env python3
"""A tool for finding the passwords required by the plugin"""

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk
import argparse
import sys

supported_services = ["org.freedesktop.NetworkManager.wireguard"]

# for parsing the data-keys
DATA_KEY_TAG = "DATA_KEY="
DATA_VAL_TAG = "DATA_VAL="
SECRET_KEY_TAG = "SECRET_KEY="
SECRET_VAL_TAG = "SECRET_VAL="

# strings used in hints
VPN_MESSAGE = "x-vpn-message:"
VPN_PASS = "password"
VPN_CERTPASS = "cert-pass"
VPN_PROXY_PASS = "http-proxy-password"

# NMSettingSecretFlags
NM_SETTING_SECRET_FLAG_NONE = 0
NM_SETTING_SECRET_FLAG_AGENT_OWNED = 1
NM_SETTING_SECRET_FLAG_NOT_SAVED = 2
NM_SETTING_SECRET_FLAG_NOT_REQUIRED = 4

class PasswordDialog(Gtk.Dialog):
    """The dialog used for communication with the User (for password entry)"""
    def __init__(self, parent, prompt, password, need_pw, certpass, need_cp, proxy_pass, need_pp):
        Gtk.Dialog.__init__(self, "Authenticate VPN", parent, 0,
                            (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                            Gtk.STOCK_OK, Gtk.ResponseType.OK))

        self.password = password if password is not None else ""
        self.certpass = certpass if certpass is not None else ""
        self.proxypass = proxy_pass if proxy_pass is not None else ""

        self.set_default_size(150, 100)
        label = Gtk.Label(prompt)
        area = Gtk.Box()
        area.set_spacing(10)
        box = self.get_content_area()
        box.set_spacing(10)
        box.add(label)

        # create the labels / text-fields for the passwords
        pw_box = Gtk.Box()
        self.pw = Gtk.Label("Password")
        self.pw_field = Gtk.Entry()
        self.pw_field.set_text(self.password)
        pw_box.set_homogeneous(True)
        pw_box.add(self.pw)
        pw_box.add(self.pw_field)
        cp_box = Gtk.Box()
        self.cp = Gtk.Label("Certificate Password")
        self.cp_field = Gtk.Entry()
        self.cp_field.set_text(self.certpass)
        cp_box.set_homogeneous(True)
        cp_box.add(self.cp)
        cp_box.add(self.cp_field)
        pp_box = Gtk.Box()
        self.pp = Gtk.Label("Proxy Password")
        self.pp_field = Gtk.Entry()
        self.pp_field.set_text(self.proxypass)        
        pp_box.set_homogeneous(True)
        pp_box.add(self.pp)
        pp_box.add(self.pp_field)

        if need_pw:
            box.add(pw_box)
        if need_cp:
            box.add(cp_box)
        if need_pp:
            box.add(pp_box)

        area.add(box)
        self.show_all()

    def get_password(self):
        """Return the password entered by the user (only valid after .run())"""
        return self.pw_field.get_text()

    def get_certpass(self):
        """Return the cert-pass entered by the user (only valid after .run())"""
        return self.cp_field.get_text()

    def get_proxypass(self):
        """Return the http-proxy-password entered by the user (only valid after .run())"""
        return self.pp_field.get_text()


def read_details(input_file):
    """Read the DATA and SECRET things passed to the stdin and create dictionaries from them"""
    data = {}
    secrets = {}
    data_key = None
    secret_key = None

    for line in input_file:
        line = line.strip()
        if line == "DONE":
            break
        else:
            if line.startswith(DATA_KEY_TAG):
                data_key = line[len(DATA_KEY_TAG):]
            elif line.startswith(DATA_VAL_TAG):
                data_val = line[len(DATA_VAL_TAG):]
                data[data_key] = data_val
            elif line.startswith(SECRET_KEY_TAG):
                secret_key = line[len(SECRET_KEY_TAG):]
            elif line.startswith(SECRET_VAL_TAG):
                secret_val = line[len(SECRET_VAL_TAG):]
                secrets[secret_key] = secret_val

    return data, secrets


def check_passwords_required(hints, name):
    """Check which passwords we need for the plugin"""
    prompt = "You need to authenticate to access the VPN '%s'" % name
    need_password, need_certpass, need_proxy_pass = False, False, False
    for hint in hints:
        if hint.startswith(VPN_MESSAGE):
            prompt = hint[len(VPN_MESSAGE):]
        elif hint == VPN_PASS:
            need_password = True
        elif hint == VPN_CERTPASS:
            need_certpass = True
        elif hint == VPN_PROXY_PASS:
            need_proxy_pass = True

    # TODO implement other logic from `get_passwords_required()` as well

    return prompt, need_password, need_certpass, need_proxy_pass


def keyring_lookup(uuid, key):
    """Look up the information stored in the keyring for uuid and key"""
    # TODO
    return "asdf"


def nm_vpn_service_plugin_get_secret_flags(data_dict, secret_name, out_flags):
    """Check if the """
    lookup_item = "%s-flags" % secret_name

    if lookup_item not in data_dict:
        # if the constructed lookup item is not in the dictionary...
        return False, out_flags
    else:
        try:
            entry = data_dict[lookup_item]
            flag = int(entry)
            # check if the flag is one of the NMSecretSettingFlags
            if flag not in [0,1,2,4] or str(flag) != entry:
                return False, out_flags
            return True, flag
        except:
            return False, out_flags


def find_existing_passwords(data_dict, secrets_dict, vpn_uuid, need_pass, need_certpass, need_proxypass):
    """Check if any of the required passwords can be found in the secrets_dict or the keyring"""
    pw_flags = NM_SETTING_SECRET_FLAG_NONE
    cp_flags = NM_SETTING_SECRET_FLAG_NONE
    pp_flags = NM_SETTING_SECRET_FLAG_NONE
    stored_pw = None
    stored_cp = None
    stored_pp = None

    # password
    # check if the DATA dictionary contains any flags regarding the password
    # and if so, check if it is anything else than NM_SETTING_SECRET_FLAG_NOT_SAVED
    tmp, pw_flags = nm_vpn_service_plugin_get_secret_flags(data_dict, VPN_PASS, pw_flags)
    if pw_flags != NM_SETTING_SECRET_FLAG_NOT_SAVED:
        # check out the SECRETS dictionary
        # or, if that fails
        # check out the keyring (TODO)
        if VPN_PASS in secrets_dict:
            stored_pw = secrets_dict[VPN_PASS]
        else:
            pass
            # stored_pw = keyring_lookup(vpn_uuid, VPN_PASS)

    # certpass
    tmp, cp_flags = nm_vpn_service_plugin_get_secret_flags(data_dict, VPN_CERTPASS, cp_flags)
    if cp_flags != NM_SETTING_SECRET_FLAG_NOT_SAVED:
        if VPN_CERTPASS in secrets_dict:
            stored_cp = secrets_dict[VPN_CERTPASS]
        else:
            pass
            # stored_cp = keyring_lookup(vpn_uuid, VPN_CERTPASS)
    
    # proxy
    tmp, pp_flags = nm_vpn_service_plugin_get_secret_flags(data_dict, VPN_PROXY_PASS, pp_flags)
    if pp_flags != NM_SETTING_SECRET_FLAG_NOT_SAVED:
        if VPN_PROXY_PASS in secrets_dict:
            stored_pp = secrets_dict[VPN_PROXY_PASS]
        else:
            pass
            # stored_pp = keyring_lookup(vpn_uuid, VPN_PROXY_PASS)

    return stored_pw, stored_cp, stored_pp


def wait_for_quit():
    """Wait until we read QUIT from stdin"""
    for line in sys.stdin:
        line = line.strip()
        if line == "QUIT":
            break


descr = ""
epilog = ""

parser = argparse.ArgumentParser(description=descr, epilog=epilog)

parser.add_argument("-r", "--reprompt", type=str, help="Reprompt for password")
parser.add_argument("-u", "--uuid", type=str, help="UUID of VPN connection")
parser.add_argument("-n", "--name", type=str, help="Name of VPN connection")
parser.add_argument("-s", "--service", type=str, help="VPN service type")
parser.add_argument("-i", "--allow-interaction", action="store_true", default=False, help="Allow user interaction")
parser.add_argument("--external-ui-mode", action="store_true", default=False, help="External UI mode")
parser.add_argument("-t", "--hint", action="append", help="Hints from the VPN plugin")

args = parser.parse_args()
canceled = False
hints = args.hint
ext_ui = args.external_ui_mode
retry = args.reprompt
interactive = args.allow_interaction
uuid = args.uuid
name = args.name
service = args.service
if hints is None:
    hints = []

if uuid is None or name is None or service is None:
    print("UUID (-u), Name (-n) and Service (-s) have to be provided", file=sys.stderr)
    exit(1)

if service not in supported_services:
    print("The service '%s' is not supported" % service, file=sys.stderr)
    print("Supported services: %s" % supported_services, file=sys.stderr)
    exit(1)

if ext_ui:
    print("Sorry, but external UI is not supported", file=sys.stderr)

# read data and secrets from stdin until "DONE", in the format
#
# DATA_KEY=key
# DATA_VAL=value
# SECRET_KEY=key
# SECRET_VAL=value
# DONE
data, secrets = read_details(sys.stdin)
if not data and not secrets:
    # sys.exit(1)
    pass

print(data)
print(secrets)

# check, which passwords are required
prompt, need_password, need_certpass, need_proxy_pass = check_passwords_required(hints, name)

if need_password or need_certpass or need_proxy_pass:

    # find whatever we need in the secrets map or the keyring (TODO)
    pw, cp, pp = find_existing_passwords(data, secrets, uuid, need_password, need_certpass, need_proxy_pass)
    required_secrets = False

    # check if there is anything left we need
    if need_password and pw is None:
        required_secrets = True
    if need_certpass and cp is None:
        required_secrets = True
    if need_proxy_pass and pp is None:
        required_secrets = True

    # if there is, we have to ask the user
    if interactive and (required_secrets or retry):
        dialog = PasswordDialog(None, prompt,
                                pw, need_password,
                                cp, need_certpass,
                                pp, need_proxy_pass)
        resp = dialog.run()

        if resp == Gtk.ResponseType.OK:
            # fetch what we need from the dialog
            if need_password:
                pw = dialog.get_password()
            if need_certpass:
                cp = dialog.get_certpass()
            if need_proxy_pass:
                pp = dialog.get_proxypass()
        else:
            canceled = True

    # if the dialog wasn't cancelled or the session wasn't interactive at all,
    # print to stdout what we found out
    if not canceled:
        # print whatever we found out
        if pw is not None:
            print("%s\n%s" % (VPN_PASS, pw))
        if cp is not None:
            print("%s\n%s" % (VPN_CERTPASS, cp))
        if pp is not None:
            print("%s\n%s" % (VPN_PROXY_PASS, pp))
        print("\n\n", end="")

        # wait for QUIT from the stdin
        wait_for_quit()

exit(1 if canceled else 0)
