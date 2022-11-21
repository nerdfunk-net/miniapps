#!/usr/bin/env python

import argparse
import json
import requests
from helper.config import readConfig
from helper.cisco import DeviceConfig


# set default config file to your needs
default_config_file = "./config.yaml"

def update_primary_adress(config, data_add_address, result):
    # please notice: check config.yaml and check if a // is not part of the URL!
    url_add_adress = "%s/onboarding/updateprimary" % config["sot"]["api_endpoint"]
    r = requests.post(url=url_add_adress, json=data_add_address)

    if r.status_code != 200:
        result['logs'].append('got status code %i' % r.status_code)
    else:
        # we got a json. parse it and check if we have a success or not
        response = json.loads(r.content)
        if response["success"]:
            result['success'].append(True)
            result['logs'].append("address %s set as primary" % data_add_address['address'])
        else:
            result['success'].append(False)
            if "reason" in response:
                result['logs'].append("address is not primary; %s" % response["reason"])
            else:
                result['logs'].append("address is not primary; unknown reason")

def send_request(url, config, json_data, result, item="", success=""):

    # please notice: check config.yaml and check if a // is not part of the URL!
    url_request = "%s/onboarding/%s" % (config["sot"]["api_endpoint"],url)
    r = requests.post(url=url_request, json=json_data)

    if r.status_code != 200:
        result['logs'].append('got status code %i' % r.status_code)
    else:
        # we got a json. parse it and check if we have a success or not
        response = json.loads(r.content)
        if response["success"]:
            result['success'].append(True)
            result['logs'].append("%s %s" % (item,success))
        else:
            result['success'].append(False)
            if "reason" in response:
                result['logs'].append("%s failed; %s" % (item, response["reason"]))
            else:
                result['logs'].append("interface updated; unknown reason")

def onboarding():

    parser = argparse.ArgumentParser()
    parser.add_argument('--deviceconfig', type=str, required=True)
    parser.add_argument('--site', type=str, required=False)
    parser.add_argument('--role', type=str, required=False)
    parser.add_argument('--manufacturer', type=str, required=False)
    parser.add_argument('--devicetype', type=str, required=False)
    parser.add_argument('--status', type=str, required=False)
    parser.add_argument('--config', type=str, required=False)

    args = parser.parse_args()

    # read config
    if args.config is not None:
        config_file = args.config
    else:
        config_file = default_config_file
    config = readConfig(config_file)

    # read device config and parse it
    ciscoconf = DeviceConfig(args.deviceconfig)

    # set tags
    if 'tags' in config['onboarding']:
        if 'interfaces' in config['onboarding']['tags']:
            for tag in config['onboarding']['tags']['interfaces']:
                ciscoconf.tag_interfaces(tag, config['onboarding']['tags']['interfaces'][tag])

    # we use a dict to store our results
    result = {}
    result['logs'] = []
    result['success'] = []

    # add device to sot
    data_add_device = {
        "name": ciscoconf.get_hostname(),
        "site": args.site or config['onboarding']['defaults']['site'],
        "role": args.role or config['onboarding']['defaults']['role'],
        "devicetype": args.devicetype or config['onboarding']['defaults']['devicetype'],
        "manufacturer": args.manufacturer or config['onboarding']['defaults']['manufacturer'],
        "platform": args.manufacturer or config['onboarding']['defaults']['platform'],
        "status": args.status or config['onboarding']['defaults']['status']
    }
    send_request("adddevice",
                 config,
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
                     config,
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
                         config,
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
                     config,
                     data_add_vlan,
                     result,
                     "vlan %s" % vid,
                     "added to sot")

    # check if we have Etherchannels
    for name in interfaces:
        interface = interfaces[name]
        if 'lag' in interface:
            #pc = "Port-channel %s" % interface["lag"]["group"]
            lag_data = {"lag": "Port-channel %s" % interface["lag"]["group"]}
            newconfig = {
                "name": ciscoconf.get_hostname(),
                "interface": name,
                "config": lag_data
            }
            send_request("updateinterface",
                          config,
                          newconfig,
                          result,
                          "interface %s" % name,
                          "updated in sot")

    # setting switchport
    for name in interfaces:
        interface = interfaces[name]
        mode = None
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
            else:
                data = None

            if data is not None:
                newconfig = {
                    "name": ciscoconf.get_hostname(),
                    "interface": name,
                    "config": data
                }
                send_request("updateinterface",
                             config,
                             newconfig,
                             result,
                             "switchport %s" % name,
                             "updated in sot")

    # setting tags
    for name in interfaces:
        interface = interfaces[name]
        if 'tags' in interface:
            list = ",".join(interface['tags'])
            newconfig = {
                "name": ciscoconf.get_hostname(),
                "interface": name,
                "config": {"tags": list}
            }
            send_request("updateinterface",
                         config,
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
                         config,
                         data_set_primary,
                         result,
                         "primary address %s" % ciscoconf.get_ipaddress(iface),
                         "updated in sot")
            break

    print (json.dumps(result, indent=4))
    #print (json.dumps(ciscoconf.get_config(),indent=4))

if __name__ == "__main__":
    onboarding()