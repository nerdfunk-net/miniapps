#!/usr/bin/env python

import argparse
import json
import sys
import pytricia
import yaml

from helper.cisco import DeviceConfig
from helper.config import read_config
from helper.sot import send_request, get_file

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
    parser.add_argument('--deviceconfig', type=str, required=True)
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
    repo = args.repo or config['files']['sites']['repo']
    filename = args.prefixe or config['files']['sites']['filename']
    prefixe_str = get_file(config["sot"]["api_endpoint"],
                           repo,
                           filename)

    prefixe = None
    try:
        prefixe_yaml = yaml.safe_load(prefixe_str)
        if prefixe_yaml is not None and 'prefixe' in prefixe_yaml:
            prefixe = prefixe_yaml['prefixe']
    except Exception as exc:
        print ("got exception: %s" % exc)
        sys.exit(-1)

    # read device config and parse it
    ciscoconf = DeviceConfig(args.deviceconfig)

    # get primary address
    primary_address = get_primary_address(config['onboarding']['defaults']['interface'],
                                          ciscoconf)['config']['primary_ip4']

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
    send_request("adddevice",
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
        send_request("addinterface",
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
            send_request("addaddress",
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
            "site": args.site or config['onboarding']['defaults']['site']
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
                        "site": args.site or config['onboarding']['defaults']['site']
                        }
            elif mode == 'tagged':
                # check if we have allowed vlans
                if 'vlan' in interface['switchport'] and \
                        'range' not in interface['switchport']:
                    vlans = ",".join(interface['switchport']['vlan'])
                    data = {"mode": "tagged",
                            "tagged": vlans,
                            "site": args.site or config['onboarding']['defaults']['site']
                            }

            if data is not None:
                newconfig = {
                    "name": ciscoconf.get_hostname(),
                    "interface": name,
                    "config": data
                }
                send_request("updateinterface",
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
            send_request("updateinterface",
                         config["sot"]["api_endpoint"],
                         newconfig,
                         result,
                         "tags %s" % interface['tags'],
                         "set in sot")

    # set primary IP of device
    for iface in config['onboarding']['defaults']['interface']:
        if ciscoconf.get_ipaddress(iface) is not None:
            new_addr = {"primary_ip4": ciscoconf.get_ipaddress(iface)}
            data_set_primary = {
                "name": ciscoconf.get_hostname(),
                "config": new_addr
            }
            send_request("updatedevice",
                         config["sot"]["api_endpoint"],
                         data_set_primary,
                         result,
                         "primary address %s" % ciscoconf.get_ipaddress(iface),
                         "updated in sot")
            break

    print(json.dumps(result, indent=4))
    # print (json.dumps(ciscoconf.get_config(),indent=4))


def get_primary_address(interfaces, cisco_config):
    for iface in interfaces:
        if cisco_config.get_ipaddress(iface) is not None:
            new_addr = {"primary_ip4": cisco_config.get_ipaddress(iface)}
            data_set_primary = {
                "name": cisco_config.get_hostname(),
                "config": new_addr
            }
            return data_set_primary

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
