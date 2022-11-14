#!/usr/bin/env python

import argparse
import requests
import json
import yaml


default_config_file = "./config.yaml"

def readConfig(filename):
    """
    read config from file
    Returns: json
    """
    with open(filename) as f:
        return yaml.safe_load(f.read())

def add_device():

    parser = argparse.ArgumentParser()
    parser.add_argument('--device', type=str, required=True)
    parser.add_argument('--site', type=str, required=True)
    parser.add_argument('--role', type=str, required=True)
    parser.add_argument('--manufacturer', type=str, required=True)
    parser.add_argument('--ipv4', type=str, required=True)
    parser.add_argument('--type', type=str, required=True)
    parser.add_argument('--status', type=str, required=False)
    parser.add_argument('--deviceconfig', type=str, required=False)
    parser.add_argument('--config', type=str, required=False)

    args = parser.parse_args()

    # read config file if config.args is set
    if args.deviceconfig:
        with open(args.deviceconfig, 'r') as file:
            deviceconfig = file.read().replace('\n', '')
    else:
        deviceconfig = ""

    # read config
    if args.config is not None:
        config_file = args.config
    else:
        config_file = default_config_file

    config = readConfig(config_file)

    data = {
        "name": args.device,
        "ipv4": args.ipv4,
        "site": args.site,
        "role": args.role,
        "type": args.type,
        "manufacturer": args.manufacturer,
        "status": args.status,
        "config": deviceconfig
    }

    r = requests.post(url = config["api_endpoint"], json = data)

    if r.status_code != 200:
        print (r.status_code)
        print (r.content)
    else:
        # we got a json. parse it and check if we have a success or not
        response = json.loads(r.content)
        if response["success"]:
            print ("device added")
        else:
            if "reason" in response:
                print ("device not added; %s" % response["reason"])
            else:
                print ("device not added; unknown reason")



if __name__ == "__main__":
    add_device()