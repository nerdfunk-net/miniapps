#!/usr/bin/env python

import argparse
import json
import sys
import pytricia
import yaml
import getpass
import socket
import os
import json
from dotenv import load_dotenv, dotenv_values
from helper.ciscoconfig import DeviceConfig
from helper import helper
from helper import devicemanagement as dm
from collections import defaultdict


# set default config file to your needs
default_config_file = "./config.yaml"


def onboarding(device_facts, raw_device_config, onboarding_config, prefixe):

    # set default values
    # we use a defaultdict to store our results
    result = defaultdict(dict)

    # get cisco config object and parse config
    ciscoconf = DeviceConfig(raw_device_config)

    # we need the fqdn of the device
    if device_facts is not None and 'fqdn' in device_facts:
        device_fqdn = device_facts['fqdn']
    else:
        # get fqdn from config instead
        device_fqdn = ciscoconf.get_fqdn()

    # get primary address of the device
    # the primary address is the ip address of the 'default' interface.
    # in most cases this is the Loopback or the Management interface
    # the interfaces we look at can be configured in our onboarding config
    pa = get_primary_address(device_fqdn,
                             onboarding_config['onboarding']['defaults']['interface'],
                             ciscoconf)
    if pa is not None:
        primary_address = pa['config']['primary_ip4']
    else:
        # no primary interface found. Get IP of the device
        print("no primary ip found using %s" % device_facts['args.device'])
        primary_address = socket.gethostbyname(device_facts['args.device'])

    # get default values for primary ip
    primary_defaults = get_prefix_defaults(prefixe, primary_address)

    # check if we have all necessary defaults
    list_def = ['site', 'role', 'devicetype', 'manufacturer', 'platform', 'status']
    for i in list_def:
        if i not in primary_defaults:
            print("%s missing. Please add %s to your default or set as arg" % (i, i))
            return result

    # set tags
    if 'tags' in onboarding_config['onboarding']:
        if 'interfaces' in onboarding_config['onboarding']['tags']:
            for tag in onboarding_config['onboarding']['tags']['interfaces']:
                ciscoconf.tag_interfaces(tag, onboarding_config['onboarding']['tags']['interfaces'][tag])

    # add device to sot
    data_add_device = {
        "name": device_fqdn,
        "site": args.site or primary_defaults['site'],
        "role": args.role or primary_defaults['role'],
        "devicetype": args.devicetype or primary_defaults['devicetype'],
        "manufacturer": args.manufacturer or primary_defaults['manufacturer'],
        "platform": args.manufacturer or primary_defaults['platform'],
        "status": args.status or primary_defaults['status']
    }

    # send_request is our helper function to call the network abstraction layer
    result[device_fqdn]['device'] = helper.send_request("adddevice",
                                                        onboarding_config["sot"]["api_endpoint"],
                                                        data_add_device)

    """
    loop through all interfaces and update/add item to sot
    """
    interfaces = ciscoconf.get_interfaces()
    for name in interfaces:

        # add interface to sot
        interface = interfaces[name]
        if 'shutdown' in interface:
            enabled = False
        else:
            enabled = True
        data_add_interface = {
            "name": device_fqdn,
            "interface": name,
            "interfacetype": interface['type'],
            "enabled": enabled,
            "description": interface['description']
        }
        result[device_fqdn][name] = helper.send_request("addinterface",
                                                        onboarding_config["sot"]["api_endpoint"],
                                                        data_add_interface)

        # add IP address to interface
        if ciscoconf.get_ipaddress(interface['name']) is not None:
            addr = ciscoconf.get_ipaddress(interface['name'])
            data_add_address = {
                "name": device_fqdn,
                "interface": name,
                "address": addr
            }
            result[device_fqdn][name][addr] = helper.send_request("addaddress",
                                                                  onboarding_config["sot"]["api_endpoint"],
                                                                  data_add_address)

        # check if we have Etherchannels
        if 'lag' in interface:
            lag_data = {"lag": "Port-channel %s" % interface["lag"]["group"]}
            newconfig = {
                "name": device_fqdn,
                "interface": name,
                "config": lag_data
            }
            result[device_fqdn][name]['portchannel'] = send_request("updateinterface",
                                                                    onboarding_config["sot"]["api_endpoint"],
                                                                    newconfig)
        # setting switchport
        if 'switchport' in interface:
            mode = interface['switchport']['mode']
            data = {}
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
                    "name": device_fqdn,
                    "interface": name,
                    "config": data
                }
                result[device_fqdn][name]['switchport'] = helper.send_request("updateinterface",
                                                                              onboarding_config["sot"]["api_endpoint"],
                                                                              newconfig)

        # setting tags of interface
        if 'tags' in interface:
            tag_list = ",".join(interface['tags'])
            newconfig = {
                "name": device_fqdn,
                "interface": name,
                "config": {"tags": tag_list}
            }
            result[device_fqdn][name]['tags'] = helper.send_request("updateinterface",
                                                                    onboarding_config["sot"]["api_endpoint"],
                                                                    newconfig)

    # add vlans
    vlans = ciscoconf.get_vlans()
    for vid in vlans:
        data_add_vlan = {
            "vid": vid,
            "name": vlans[vid]['name'],
            "status": "active",
            "site": args.site or primary_defaults['site']
        }
        result[device_fqdn]['vlan'][vid] = send_request("addvlan",
                                                        onboarding_config["sot"]["api_endpoint"],
                                                        data_add_vlan)

    # set primary IP/Interface of device
    iface = ciscoconf.get_interface_by_address(primary_address)
    new_addr = {"primary_ip4": primary_address,
                "interface": iface}

    if new_addr is not None and iface is not None:
        data_set_primary = {
            "name": device_fqdn,
            "config": new_addr
        }
        result[device_fqdn]['primary_ip'] = helper.send_request("updatedevice",
                            onboarding_config["sot"]["api_endpoint"],
                            data_set_primary)
    else:
        result[device_fqdn]['primary_ip'] = \
            "no primary interface found; device is accessible only with hostname/ip you used"

    #print(json.dumps(dict(result),indent=4))
    return result


def get_primary_address(device_fqdn, interfaces, cisco_config):
    for iface in interfaces:
        if cisco_config.get_ipaddress(iface) is not None:
            new_addr = {"primary_ip4": cisco_config.get_ipaddress(iface)}
            return {
                "name": device_fqdn,
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


def get_device_config(device, args):

    # default values
    device_facts = None
    username = None
    password = None

    # either we read the device config from a file or we
    # connect to the device and get the running config
    if args.deviceconfig is not None:
        # read device config from file
        with open(args.deviceconfig, 'r') as file:
            raw_config = file.read().splitlines()
    elif device is not None:
        """
        read the running config from the device
        we need the username and password.
        credentials are either configuted in our config
        or must be entered by the user
        """
        if args.profile is not None:
            profile = args.profile
            account = helper.get_profile(onboarding_config, profile)
            if not account['success']:
                print("could not retrieve username and password")
            else:
                username = account.get('username')
                password = account.get('password')
        if username is None:
            username = input("Username (%s): " % getpass.getuser())
            if username == "":
                username = getpass.getuser()
        elif args.username is not None:
            username = args.username

        if password is None and args.password is None:
            password = getpass.getpass(prompt="Enter password for %s: " % username)
        else:
            if args.password is not None:
                password = args.password

        # open connection to device
        conn = dm.open_connection(device,
                                  username,
                                  password,
                                  args.platform,
                                  args.port)

        # check connection
        if conn is None:
            print("could not get connection to device; check properties like platform")
            sys.exit()

        device_facts = dm.get_facts(conn)
        device_facts.update({'args.device': device})
        device_config = dm.get_config(conn, "running-config").splitlines()
        conn.close()

    else:
        print("either device or deviceconfig must be specified")
        sys.exit(-1)

    return {
        "device_facts": device_facts,
        "device_config": device_config,
    }


if __name__ == "__main__":

    """
    There is only on mandatory argument. We need the device config or the device.
    The other arguments can override the default values configured
    in our config file.
    """
    parser = argparse.ArgumentParser()
    # the user can enter a different config file
    parser.add_argument('--config', type=str, required=False)
    # we need the config. The config can be read or retrieved
    # from the device
    parser.add_argument('--deviceconfig', type=str, required=False)
    parser.add_argument('--device', type=str, required=False)
    parser.add_argument('--port', type=int, default=22, required=False)
    # we need username and password if the config is retrieved by the device
    # credentials can be configured using a profile
    # have a look at the config file
    parser.add_argument('--username', type=str, required=False)
    parser.add_argument('--password', type=str, required=False)
    parser.add_argument('--profile', type=str, required=False)
    # we need some mandatory properties
    # either these properties are part of the prefixe
    parser.add_argument('--prefixe', type=str, required=False)
    parser.add_argument('--repo', type=str, required=False)
    # or the properties must be specified using the following args
    parser.add_argument('--site', type=str, required=False)
    parser.add_argument('--role', type=str, required=False)
    parser.add_argument('--manufacturer', type=str, required=False)
    parser.add_argument('--devicetype', type=str, required=False)
    parser.add_argument('--platform', type=str, default="ios", required=False)
    parser.add_argument('--status', type=str, required=False)

    args = parser.parse_args()

    # set defaults
    prefixe = None

    # Get the path to the directory this file is in
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    # Connect the path with the '.env' file name
    load_dotenv(os.path.join(BASEDIR, '.env'))
    # you can get the env variable by using var = os.getenv('varname')

    # read onboarding config
    if args.config is not None:
        config_file = args.config
    else:
        config_file = default_config_file
    onboarding_config = helper.read_config(config_file)

    # get default values of prefixes. This is needed only once
    repo = args.repo or onboarding_config['files']['prefixe']['repo']
    filename = args.prefixe or onboarding_config['files']['prefixe']['filename']
    prefixe_str = helper.get_file(onboarding_config["sot"]["api_endpoint"],
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

    """
    we have the static values. Now get the config of each device and call
    onboarding.
    """

    result = defaultdict(dict)
    if ',' in args.device:
        devices = args.device.split(',')
        for device in devices:
            print("processing %s" % device)
            values = get_device_config(device, args)
            ret = onboarding(values['device_facts'],
                             values['device_config'],
                             onboarding_config,
                             prefixe)
            result.update(ret)
    elif args.device is not None:
        # we have only one device
        values = get_device_config(args.device, args)
        result = onboarding(values['device_facts'],
                            values['device_config'],
                            onboarding_config,
                            prefixe)
    elif args.deviceconfig is not None:
        # config file specified
        values = get_device_config(None, args)
        result = onboarding(values['device_facts'],
                            values['device_config'],
                            onboarding_config,
                            prefixe)

    """
    device
     - interface
      - ip address
      - etherchannel
      - switchport
      - tags
     - primary ip
     - vlan
    """
    print(json.dumps(dict(result),indent=4))
