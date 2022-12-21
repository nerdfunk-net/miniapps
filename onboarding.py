#!/usr/bin/env python

import argparse
import json
import sys
import pytricia
import yaml
import getpass
import socket

from helper.cisco import DeviceConfig
from helper.config import read_config
from helper import sot

# set default config file to your needs
default_config_file = "./config.yaml"


def onboarding():
    """
    main function that reads config and add device including interfaces, vlans
    and other necessary items

    Returns: -

    """

    """
    There is only on mandatory argument. We need the device config.
    The other arguments can override the default values configured
    in our config file.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--deviceconfig', type=str, required=False)
    parser.add_argument('--device', type=str, required=False)
    parser.add_argument('--os', type=str, default="ios", required=False)
    parser.add_argument('--port', type=int, default=22, required=False)
    parser.add_argument('--username', type=str, required=False)
    parser.add_argument('--password', type=str, required=False)
    parser.add_argument('--profile', type=str, required=False)
    parser.add_argument('--site', type=str, required=False)
    parser.add_argument('--role', type=str, required=False)
    parser.add_argument('--manufacturer', type=str, required=False)
    parser.add_argument('--devicetype', type=str, required=False)
    parser.add_argument('--status', type=str, required=False)
    parser.add_argument('--config', type=str, required=False)
    parser.add_argument('--repo', type=str, required=False)
    parser.add_argument('--prefixe', type=str, required=False)

    args = parser.parse_args()

    # read config
    if args.config is not None:
        config_file = args.config
    else:
        config_file = default_config_file
    config = read_config(config_file)

    # get default values of prefixes
    prefixe = None

    repo = args.repo or config['files']['prefixe']['repo']
    filename = args.prefixe or config['files']['prefixe']['filename']
    prefixe_str = sot.get_file(config["sot"]["api_endpoint"],
                               repo,
                               filename)

    if prefixe_str is None:
        print("could not load prefixe")
        sys.exit(-1)

    try:
        prefixe_yaml = yaml.safe_load(prefixe_str)
        if prefixe_yaml is not None and 'prefixe' in prefixe_yaml:
            prefixe = prefixe_yaml['prefixe']
    except Exception as exc:
        print("got exception: %s" % exc)
        sys.exit(-1)

    # either we read the device config or we
    # connect to the device and get the current config

    if args.deviceconfig is not None:
        # read device config and parse it
        ciscoconf = DeviceConfig()
        ciscoconf.read_config(args.deviceconfig)
    elif args.device is not None:
        # check what login to use
        username = None
        password = None

        if args.profile is not None:
            if args.profile in config['logins']:
                if 'username' in config['logins'][args.profile]:
                    username = config['logins'][args.profile]['username']
                if 'password' in config['logins'][args.profile]:
                    password = config['logins'][args.profile]['password']
            else:
                print("Unknown profile %s" % args.profile)
                sys.exit(-1)

        if username is None:
            if args.username is None:
                username = input("Username (%s): " % getpass.getuser())
                if username == "":
                    username = getpass.getuser()
            else:
                username = args.username

        if password is None and args.password is None:
            password = getpass.getpass(prompt="Enter password for %s: " % username)
        else:
            if args.password is not None:
                password = args.password

        os = args.os
        port = args.port
        ciscoconf = DeviceConfig()
        ciscoconf.get_device_config(args.device, username, password, os, port)

    # get primary address
    # the primary address is the ip address of the 'default' interface.
    # in most cases this is the Loopback or the Management interface
    # the interfaces to look at can be configured in our onboarding config
    pa = get_primary_address(config['onboarding']['defaults']['interface'], ciscoconf)
    if pa is not None:
        primary_address = pa['config']['primary_ip4']
    else:
        # no primary interface found. Get IP of the device
        primary_address = socket.gethostbyname(args.device)

    # get default values for primary ip
    primary_defaults = get_prefix_defaults(prefixe, primary_address)

    # check if we have all necessary defaults
    list_def = ['site', 'role', 'devicetype', 'manufacturer', 'platform', 'status']
    for i in list_def:
        if i not in primary_defaults:
            print ("%s missing. Please add %s to your default or set as arg" % (i, i))
            sys.exit(-1)

    # set tags
    if 'tags' in config['onboarding']:
        if 'interfaces' in config['onboarding']['tags']:
            for tag in config['onboarding']['tags']['interfaces']:
                ciscoconf.tag_interfaces(tag, config['onboarding']['tags']['interfaces'][tag])

    # we use a dict to store our results
    result = {'logs': [], 'success': []}

    # add device to sot
    data_add_device = {
        "name": ciscoconf.get_hostname(),
        "site": args.site or primary_defaults['site'],
        "role": args.role or primary_defaults['role'],
        "devicetype": args.devicetype or primary_defaults['devicetype'],
        "manufacturer": args.manufacturer or primary_defaults['manufacturer'],
        "platform": args.manufacturer or primary_defaults['platform'],
        "status": args.status or primary_defaults['status']
    }

    # send request is our helper function to call the network abstraction layer
    sot.send_request("adddevice",
                 config["sot"]["api_endpoint"],
                 data_add_device,
                 result,
                 item="device %s" % ciscoconf.get_hostname(),
                 success="added to sot")

    # add Interfaces and IP addresses
    interfaces = ciscoconf.get_interfaces()
    for name in interfaces:
        interface = interfaces[name]
        if 'shutdown' in interface:
            enabled = False
        else:
            enabled = True
        data_add_interface = {
            "name": ciscoconf.get_hostname(),
            "interface": name,
            "interfacetype": interface['type'],
            "enabled": enabled,
            "description": interface['description']
        }
        sot.send_request("addinterface",
                     config["sot"]["api_endpoint"],
                     data_add_interface,
                     result,
                     item="interface %s" % name,
                     success="added to sot")

        if ciscoconf.get_ipaddress(interface['name']) is not None:
            data_add_address = {
                "name": ciscoconf.get_hostname(),
                "interface": name,
                "address": ciscoconf.get_ipaddress(interface['name'])
            }
            sot.send_request("addaddress",
                         config["sot"]["api_endpoint"],
                         data_add_address,
                         result,
                         "address %s" % ciscoconf.get_ipaddress(interface['name']),
                         "added to sot")

    # add vlans
    vlans = ciscoconf.get_vlans()
    for vid in vlans:
        data_add_vlan = {
            "vid": vid,
            "name": vlans[vid]['name'],
            "status": "active",
            "site": args.site or primary_defaults['site']
        }
        send_request("addvlan",
                     config["sot"]["api_endpoint"],
                     data_add_vlan,
                     result,
                     "vlan %s" % vid,
                     "added to sot")

    # check if we have Etherchannels
    for name in interfaces:
        interface = interfaces[name]
        if 'lag' in interface:
            lag_data = {"lag": "Port-channel %s" % interface["lag"]["group"]}
            newconfig = {
                "name": ciscoconf.get_hostname(),
                "interface": name,
                "config": lag_data
            }
            send_request("updateinterface",
                         config["sot"]["api_endpoint"],
                         newconfig,
                         result,
                         "interface %s" % name,
                         "updated in sot")

    # setting switchport
    for name in interfaces:
        interface = interfaces[name]
        data = None
        if 'switchport' in interface:
            mode = interface['switchport']['mode']
            if mode == 'access':
                data = {"mode": "access",
                        "untagged": interface['switchport']['vlan'],
                        "site": args.site or primary_defaults['site']
                        }
            elif mode == 'tagged':
                # check if we have allowed vlans
                if 'vlan' in interface['switchport'] and \
                        'range' not in interface['switchport']:
                    vlans = ",".join(interface['switchport']['vlan'])
                    data = {"mode": "tagged",
                            "tagged": vlans,
                            "site": args.site or primary_defaults['site']
                            }

            if data is not None:
                newconfig = {
                    "name": ciscoconf.get_hostname(),
                    "interface": name,
                    "config": data
                }
                sot.send_request("updateinterface",
                             config["sot"]["api_endpoint"],
                             newconfig,
                             result,
                             "switchport %s" % name,
                             "updated in sot")

    # setting tags
    for name in interfaces:
        interface = interfaces[name]
        if 'tags' in interface:
            tag_list = ",".join(interface['tags'])
            newconfig = {
                "name": ciscoconf.get_hostname(),
                "interface": name,
                "config": {"tags": tag_list}
            }
            sot.send_request("updateinterface",
                         config["sot"]["api_endpoint"],
                         newconfig,
                         result,
                         "tags %s" % interface['tags'],
                         "set in sot")

    # set primary IP/Interface of device
    iface = ciscoconf.get_interface_by_address(primary_address)
    new_addr = {"primary_ip4": primary_address,
                "interface": iface}

    if new_addr is not None and iface is not None:
        data_set_primary = {
            "name": ciscoconf.get_hostname(),
            "config": new_addr
        }
        sot.send_request("updatedevice",
                         config["sot"]["api_endpoint"],
                         data_set_primary,
                         result,
                         "primary address %s" % ciscoconf.get_ipaddress(iface),
                         "updated in sot")
    else:
        print("no primary interface found; device is accessible only with hostname/ip you used")

    print(json.dumps(result, indent=4))
    # print (json.dumps(ciscoconf.get_config(),indent=4))


def get_primary_address(interfaces, cisco_config):
    for iface in interfaces:
        if cisco_config.get_ipaddress(iface) is not None:
            new_addr = {"primary_ip4": cisco_config.get_ipaddress(iface)}
            return {
                "name": cisco_config.get_hostname(),
                "config": new_addr,
                "interface": iface
            }

    return None


def get_prefix_path(prefixe, ip):
    prefix_path = []
    pyt = pytricia.PyTricia()

    # build pytricia tree
    for prefix_ip in prefixe:
        pyt.insert(prefix_ip, prefix_ip)

    prefix = pyt.get(ip)
    prefix_path.append(prefix)

    parent = pyt.parent(prefix)
    while (parent):
        prefix_path.append(parent)
        parent = pyt.parent(parent)
    return prefix_path[::-1]


def get_prefix_defaults(prefixe, ip):

    if prefixe is None:
        return {}

    prefix_path = get_prefix_path(prefixe, ip)
    defaults = {}

    for prefix in prefix_path:
        defaults.update(prefixe[prefix])

    return defaults


if __name__ == "__main__":
    onboarding()
