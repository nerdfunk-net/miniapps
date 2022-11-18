#!/usr/bin/env python

import argparse
import json
import requests
from helper.config import readConfig
from helper.cisco import DeviceConfig


# set default config file to your needs
default_config_file = "./config.yaml"

def add_device(config, data_add_device, result):

    # please notice: check config.yaml and check if a // is not part of the URL!
    url_add_debice = "%s/onboarding/adddevice" % config["sot"]["api_endpoint"]
    r = requests.post(url=url_add_debice, json=data_add_device)

    if r.status_code != 200:
        result['logs'].append('got status code %i' % r.status_code)
    else:
        # we got a json. parse it and check if we have a success or not
        response = json.loads(r.content)
        if response["success"]:
            result['success'].append(True)
            result['logs'].append("device %s added to sot" % data_add_device['name'])
        else:
            result['success'].append(False)
            if "reason" in response:
                result['logs'].append("device not added; %s" % response["reason"])
            else:
                result['logs'].append("device not added; unknown reason")

def add_interface(config, data_add_interface, result):

    # please notice: check config.yaml and check if a // is not part of the URL!
    url_add_device = "%s/onboarding/addinterface" % config["sot"]["api_endpoint"]
    r = requests.post(url=url_add_device, json=data_add_interface)

    if r.status_code != 200:
        result['logs'].append('got status code %i' % r.status_code)
    else:
        # we got a json. parse it and check if we have a success or not
        response = json.loads(r.content)
        if response["success"]:
            result['success'].append(True)
            result['logs'].append("interface %s added to sot" % data_add_interface['interface'])
        else:
            result['success'].append(False)
            if "reason" in response:
                result['logs'].append("interface not added; %s" % response["reason"])
            else:
                result['logs'].append("interface not added; unknown reason")

def add_ipaddress(config, data_add_address, result):

    # please notice: check config.yaml and check if a // is not part of the URL!
    url_add_adress = "%s/onboarding/addaddress" % config["sot"]["api_endpoint"]
    r = requests.post(url=url_add_adress, json=data_add_address)

    if r.status_code != 200:
        result['logs'].append('got status code %i' % r.status_code)
    else:
        # we got a json. parse it and check if we have a success or not
        response = json.loads(r.content)
        if response["success"]:
            result['success'].append(True)
            result['logs'].append("address %s added to sot" % data_add_address['address'])
        else:
            result['success'].append(False)
            if "reason" in response:
                result['logs'].append("address not added; %s" % response["reason"])
            else:
                result['logs'].append("address not added; unknown reason")

def onboarding():

    parser = argparse.ArgumentParser()
    parser.add_argument('--site', type=str, required=False)
    parser.add_argument('--role', type=str, required=False)
    parser.add_argument('--manufacturer', type=str, required=False)
    parser.add_argument('--devicetype', type=str, required=False)
    parser.add_argument('--status', type=str, required=False)
    parser.add_argument('--deviceconfig', type=str, required=True)
    parser.add_argument('--config', type=str, required=False)

    args = parser.parse_args()

    # read config
    if args.config is not None:
        config_file = args.config
    else:
        config_file = default_config_file
    config = readConfig(config_file)

    # read config and parse it
    ciscoconf = DeviceConfig(args.deviceconfig)

    data_add_device = {
        "name": ciscoconf.get_hostname(),
        "site": args.site or config['onboarding']['defaults']['site'],
        "role": args.role or config['onboarding']['defaults']['role'],
        "devicetype": args.devicetype or config['onboarding']['defaults']['devicetype'],
        "manufacturer": args.manufacturer or config['onboarding']['defaults']['manufacturer'],
        "status": args.status or config['onboarding']['defaults']['status']
    }

    # set tags
    if 'tags' in config['onboarding']:
        for tag in config['onboarding']['tags']:
            ciscoconf.tag_interfaces(tag, config['onboarding']['tags'][tag])
    #print (json.dumps(ciscoconf.get_config(),indent=4))

    # we use a dict to store our results
    result = {}
    result['logs'] = []
    result['success'] = []

    # add device to sot
    add_device(config, data_add_device, result)

    # add Interface
    for interface in config['onboarding']['defaults']['interface']:
        iface = ciscoconf.get_interface(interface)
        if iface is not None:
            data_add_interface = {
                "name": ciscoconf.get_hostname(),
                "interface": interface,
                "interfacetype": iface['type'],
                #"label": iface['description']
            }
            data_add_address = {
                "name": ciscoconf.get_hostname(),
                "interface": interface,
                "address": ciscoconf.get_ipaddress(interface)
            }
            add_interface(config, data_add_interface, result)
            add_ipaddress(config, data_add_address, result)
            break

    print (json.dumps(result, indent=4))

    #print (json.dumps(ciscoconf.get_config(),indent=4))

if __name__ == "__main__":
    onboarding()