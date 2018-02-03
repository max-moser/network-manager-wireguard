#!/usr/bin/env python3
"""Carve the interesting parts out of a wireguard config file and print them to stdout such that it's easier to read them in C"""

import argparse

def is_ip4(string):
    """Check if the given string is in IPv4 format"""
    if string.count(".") == 3:
        for s in string.split("."):
            try:
                int(s)
            except:
                return False
        return True

    return False


def is_ip6(string):
    """Check if the given string is in IPv6 format"""
    if ":" in string:
        return True

    return False


def parse_ips(string):
    """Parse the IP4s and IP6s out of a comma-separated list of IPs"""
    ip4 = []
    ip6 = []

    ips = [s.strip() for s in string.split(",")]
    for ip in ips:
        if is_ip4(ip):
            ip4.append(ip)
        elif is_ip6(ip):
            ip6.append(ip)

    return ip4, ip6


parser = argparse.ArgumentParser()
parser.add_argument("config", metavar="CONFIG-FILE", help="The path of the configuration file")

args = parser.parse_args()

with open(args.config, "r") as config_file:
    lines = config_file.readlines()

    local_section = False
    for line in lines:
        line = line.strip()

        if "[Interface]" in line:
            local_section = True

        if line and not line.startswith("#"):
            if line.startswith("Address"):
                # this is the line where the local addresses are defined
                split = line.split("=")
                ip4, ip6 = parse_ips(split[1])

                print("IPv4")
                for ip in ip4:
                    print(ip)
                print("IPv6")
                for ip in ip6:
                    print(ip)
