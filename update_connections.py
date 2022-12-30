#!/usr/bin/env python

import argparse
import getpass
import json
from scrapli import Scrapli
from helper import helper
from helper import devicemanagement as dm


# set default config file to your needs
default_config_file = "./config.yaml"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--device', type=str, required=False)
    parser.add_argument('--port', type=int, default=22, required=False)
    parser.add_argument('--username', type=str, required=False)
    parser.add_argument('--password', type=str, required=False)
    parser.add_argument('--profile', type=str, required=False)
    parser.add_argument('--platform', type=str, default="cisco_iosxe", required=False)
    parser.add_argument('--config', type=str, required=False)

    args = parser.parse_args()

    # read config
    if args.config is not None:
        config_file = args.config
    else:
        config_file = default_config_file
    config = helper.read_config(config_file)

    # check what login to use
    username = None
    password = None

    if args.profile is not None:
        if args.profile in config['logins']:
            username = config['logins'].get(args.profile).get('username')
            password = config['logins'].get(args.profile).get(username)
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

    conn = dm.open_connection(args.device, username, password, args.platform)
    response = conn.send_commands(['show running-config | incl hostname',
                                   'show running-config | incl ip domain name'])

    hostname = response[0].result.split(' ')[1]
    domain = response[1].result.split('ip domain name ')[1]
    fqdn = "%s.%s" % (hostname, domain)

    # get layer2 neighbors
    response = conn.send_command("show cdp neighbors")
    result = response.genie_parse_output()

    sot_result = {'logs': [], 'success': []}

    for line in result['cdp']['index']:
        device_id = result['cdp']['index'][line]['device_id']
        local_interface = result['cdp']['index'][line]['local_interface']
        port_id = result['cdp']['index'][line]['port_id']
        print("adding %s %s %s %s" % (fqdn, local_interface, device_id, port_id))

        connection = {
            "side_a": fqdn,
            "side_b": device_id,
            "interface_a": local_interface,
            "interface_b": port_id,
            "cable_type": "cat5e"
        }
        newconfig = {
            "name": fqdn,
            "config": connection
        }
        helper.send_request("updateconnection",
                         config["sot"]["api_endpoint"],
                         newconfig,
                         sot_result,
                         item="connection",
                         success="added to sot")

    print(json.dumps(sot_result, indent=4))


if __name__ == "__main__":
    main()
