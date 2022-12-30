#!/usr/bin/env python

import argparse
import requests
import json
from helper.helper import read_config

# set default config file to your needs
default_config_file = "./config.yaml"


def add_device():

    parser = argparse.ArgumentParser()
    parser.add_argument('--device', type=str, required=True)
    parser.add_argument('--site', type=str, required=True)
    parser.add_argument('--role', type=str, required=True)
    parser.add_argument('--manufacturer', type=str, required=False)
    parser.add_argument('--devicetype', type=str, required=True)
    parser.add_argument('--status', type=str, required=False)
    parser.add_argument('--deviceconfig', type=str, required=False)
    parser.add_argument('--config', type=str, required=False)
    parser.add_argument('--ipv4', type=str, required=False)
    parser.add_argument('--interface', type=str, required=False)
    parser.add_argument('--interfacetype', type=str, required=False)

    args = parser.parse_args()

    # read config
    if args.config is not None:
        config_file = args.config
    else:
        config_file = default_config_file
    config = read_config(config_file)

    # we use a dict to store our results
    result = {'logs': [], 'success': []}

    data_add_device = {
        "name": args.device,
        "site": args.site,
        "role": args.role,
        "devicetype": args.devicetype,
        "manufacturer": args.manufacturer,
        "status": args.status
    }

    # please notice: check config.yaml and check if a // is not part of the URL!
    url_add_device = "%s/onboarding/adddevice" % config["sot"]["api_endpoint"]
    r = requests.post(url=url_add_device, json=data_add_device)

    if r.status_code != 200:
        result['logs'].append('got status code %i' % r.status_code)
    else:
        # we got a json. parse it and check if we have a success or not
        response = json.loads(r.content)
        if response["success"]:
            result['success'].append(True)
            result['logs'].append("device %s added to sot" % args.device)
        else:
            result['success'].append(False)
            if "reason" in response:
                result['logs'].append("device not added; %s" % response["reason"])
            else:
                result['logs'].append("device not added; unknown reason")

    if args.interface is not None and args.interfacetype is not None:
        data_add_interface = {
            "name": args.device,
            "interface": args.interface,
            "interfacetype": args.interfacetype
        }

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
                result['logs'].append("interface %s added to sot" % args.interface)
            else:
                result['success'].append(False)
                if "reason" in response:
                    result['logs'].append("interface not added; %s" % response["reason"])
                else:
                    result['logs'].append("interface not added; unknown reason")

    if args.ipv4 is not None:
        data_add_address = {
            "name": args.device,
            "interface": args.interface,
            "address": args.ipv4
        }

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
                result['logs'].append("address %s added to sot" % args.ipv4)
            else:
                result['success'].append(False)
                if "reason" in response:
                    result['logs'].append("address not added; %s" % response["reason"])
                else:
                    result['logs'].append("address not added; unknown reason")

    print (json.dumps(result, indent=4))


if __name__ == "__main__":
    add_device()