#!/usr/bin/env python

import argparse
import sys
import pytricia
import yaml
import getpass
import socket
import os
import json
import logging
import pprint
from dotenv import load_dotenv, dotenv_values
from helper.ciscoconfig import DeviceConfig
from helper import helper
from helper import devicemanagement as dm
from collections import defaultdict
from businesslogic import config_context as bl_cc
from businesslogic import interfaces as bl_int
from businesslogic import device as bl_device

# set default config file to your needs
default_config_file = "./config.yaml"


def onboarding_devices(result, args, device_fqdn, device_facts, raw_device_config, primary_defaults, onboarding_config):

    # add device to sot
    data_add_device = {
        "name": device_fqdn,
        "site": args.site or primary_defaults['site'],
        "role": args.role or primary_defaults['role'],
        "devicetype": args.devicetype or primary_defaults['devicetype'],
        "manufacturer": args.manufacturer or primary_defaults['manufacturer'],
        "platform": args.manufacturer or primary_defaults['platform'],
        "serial_number": device_facts["serial_number"],
        "status": args.status or primary_defaults['status']
    }

    # send_request is our helper function to call the network abstraction layer
    logging.debug("adding device %s (%s) to sot" % (device_fqdn, device_facts['model']))
    result[device_fqdn]['device'] = helper.send_request("adddevice",
                                                        onboarding_config["sot"]["api_endpoint"],
                                                        data_add_device)

    logging.debug("calling business logic of device %s to sot" % device_fqdn)
    bl_device.device(result, device_fqdn, raw_device_config, onboarding_config)


def onboarding_interfaces(result, args, device_fqdn, primary_defaults, ciscoconf, onboarding_config):

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
        logging.debug("adding %s / %s to sot" % (device_fqdn, name))
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
            logging.debug("adding %s / %s to sot" % (device_fqdn, addr))
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
            logging.debug("adding etherchannels of %s to sot" % device_fqdn)
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
                logging.debug("adding switchport of %s to sot" % device_fqdn)
                result[device_fqdn][name]['switchport'] = helper.send_request("updateinterface",
                                                                              onboarding_config["sot"]["api_endpoint"],
                                                                              newconfig)

        # setting standard tags of interface
        if 'tags' in interface:
            tag_list = ",".join(interface['tags'])
            newconfig = {
                "name": device_fqdn,
                "interface": name,
                "config": {"tags": tag_list}
            }
            logging.debug("adding tags of %s to sot" % device_fqdn)
            result[device_fqdn][name]['tags'] = helper.send_request("updateinterface",
                                                                    onboarding_config["sot"]["api_endpoint"],
                                                                    newconfig)

        # call business logic
        logging.debug("calling business logic for %s/%s" % (device_fqdn, name))
        bl_int.interface_tags(result,
                              device_fqdn,
                              name,
                              ciscoconf.get_section("interface %s" % name),
                              onboarding_config)


def onboarding_vlans(result, args, ciscoconf, onboarding_config):

    # add vlans
    vlans = ciscoconf.get_vlans()
    for vid in vlans:
        data_add_vlan = {
            "vid": vid,
            "name": vlans[vid]['name'],
            "status": "active",
            "site": args.site or primary_defaults['site']
        }
        logging.debug("adding vlan %s of %s to sot" % (vid, device_fqdn))
        result[device_fqdn]['vlan'][vid] = send_request("addvlan",
                                                        onboarding_config["sot"]["api_endpoint"],
                                                        data_add_vlan)


def onboarding_primary_ip(result, device_fqdn, primary_address, ciscoconf, onboarding_config):

    # set primary IP/Interface of device
    iface = ciscoconf.get_interface_by_address(primary_address)
    new_addr = {"primary_ip4": primary_address,
                "interface": iface}

    if new_addr is not None and iface is not None:
        data_set_primary = {
            "name": device_fqdn,
            "config": new_addr
        }
        logging.debug("setting primary IP of %s in sot" % device_fqdn)
        result[device_fqdn]['primary_ip'] = helper.send_request("updatedevice",
                                                                onboarding_config["sot"]["api_endpoint"],
                                                                data_set_primary)
    else:
        result[device_fqdn]['primary_ip'] = \
            "no primary interface found; device is accessible only with hostname/ip you used"


def onboarding_cables(conn, device_facts, onboarding_config):

    # get layer2 neighbors
    response = conn.send_command("show cdp neighbors")
    result = response.genie_parse_output()

    for line in result['cdp']['index']:
        device_id = result['cdp']['index'][line]['device_id']
        local_interface = result['cdp']['index'][line]['local_interface']
        port_id = result['cdp']['index'][line]['port_id']
        logging.debug("adding %s %s %s %s" % (device_facts['fqdn'],
                                              local_interface,
                                              device_id,
                                              port_id))

        connection = {
            "side_a": device_facts['fqdn'],
            "side_b": device_id,
            "interface_a": local_interface,
            "interface_b": port_id,
            "cable_type": "cat5e"
        }
        newconfig = {
            "name": device_facts['fqdn'],
            "config": connection
        }
        return helper.send_request("updateconnection",
                                   onboarding_config["sot"]["api_endpoint"],
                                   newconfig)


def onboarding_config_contexts(result, device_fqdn, ciscoconf, raw_device_config, onboarding_config):

    cfg_contexts = helper.get_value_from_dict(onboarding_config,['onboarding','config_context'])
    device_context = defaultdict(dict)

    # check if we have some config_context rules configured
    if cfg_contexts is None:
        result[device_fqdn]['config_context'] = "no config context configured in config"
        return

    for cfg_context in cfg_contexts:
        for section in cfg_contexts[cfg_context]:
            ctx_list = []
            cnf = ciscoconf.get_section(section)
            for i in cnf:
                ctx_list.append(i.text)
            device_context[cfg_context] = ctx_list

    device_context = bl_cc.onfig_context(result,
                                         device_fqdn,
                                         device_context,
                                         raw_device_config,
                                         onboarding_config)

    # the device_context is a dict but we need a yaml
    device_context_yaml = yaml.dump(dict(device_context),
                                    allow_unicode=True,
                                    default_flow_style=False)

    config = {
        'repo': 'config_contexts',
        'filename': device_fqdn,
        'content': "%s\n%s" % ("---", device_context_yaml),
        'action': 'overwrite',
        'pull': False,
    }

    newconfig = {
        "config": config
    }

    result[device_fqdn]['config_context'] = helper.send_request("editfile",
                                                                onboarding_config["sot"]["api_endpoint"],
                                                                newconfig)


def onboarding_backup_config(result, device_fqdn, raw_device_config, onboarding_config):

    config = {
        'repo': 'config_backup',
        'filename': device_fqdn,
        'content': raw_device_config,
        'action': 'overwrite',
        'pull': False,
    }

    newconfig = {
        "config": config
    }

    result[device_fqdn]['backup'] = helper.send_request("editfile",
                                                        onboarding_config["sot"]["api_endpoint"],
                                                        newconfig)


def onboarding(device_facts, raw_device_config, onboarding_config, prefixe):

    # set default values
    # we use a defaultdict to store our results
    result = defaultdict(dict)

    # get cisco config object and parse config
    # ciscoconfparse expects the device config as lines
    ciscoconf = DeviceConfig(raw_device_config.splitlines())

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
        logging.debug("primary address %s" % primary_address)
    else:
        # no primary interface found. Get IP of the device
        logging.info("no primary ip found using %s" % device_facts['args.device'])
        primary_address = socket.gethostbyname(device_facts['args.device'])

    # get default values for primary ip
    logging.debug("getting default values for %s" % primary_address)
    primary_defaults = get_prefix_defaults(prefixe, primary_address)

    # check if we have all necessary defaults
    list_def = ['site', 'role', 'devicetype', 'manufacturer', 'platform', 'status']
    for i in list_def:
        if i not in primary_defaults:
            logging.critical("%s missing. Please add %s to your default or set as arg" % (i, i))
            print("%s missing. Please add %s to your default or set as arg" % (i, i))
            return result

    # set tags
    if 'tags' in onboarding_config['onboarding']:
        if 'interfaces' in onboarding_config['onboarding']['tags']:
            for tag in onboarding_config['onboarding']['tags']['interfaces']:
                ciscoconf.tag_interfaces(tag, onboarding_config['onboarding']['tags']['interfaces'][tag])

    if args.onboarding:
        onboarding_devices(result,
                           args,
                           device_fqdn,
                           device_facts,
                           raw_device_config,
                           primary_defaults,
                           onboarding_config)

    if args.interfaces:
        onboarding_interfaces(result,
                              args,
                              device_fqdn,
                              primary_defaults,
                              ciscoconf,
                              onboarding_config)

    if args.vlans:
        onboarding_vlans(result, args, ciscoconf, onboarding_config)

    if args.onboarding:
        onboarding_primary_ip(result,
                              device_fqdn,
                              primary_address,
                              ciscoconf,
                              onboarding_config)

    if args.config_context:
        onboarding_config_contexts(result,
                                   device_fqdn,
                                   ciscoconf,
                                   raw_device_config,
                                   onboarding_config)

    if args.backup:
        onboarding_backup_config(result,
                                 device_fqdn,
                                 raw_device_config,
                                 onboarding_config)

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


def get_username_and_password(args):
    """
    get username and password from profile
    Args:
        args:

    Returns:
        username: str
        password: str
    """

    """
    credentials are either configured in our config
    or must be entered by the user
    """

    username = None
    password = None

    if args.profile is not None:
        logging.debug("using profile %s" % args.profile)
        profile = args.profile
        account = helper.get_profile(onboarding_config, profile)
        if not account['success']:
            logging.error("could not retrieve username and password")
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

    logging.debug("username=%s, password=%s" % (username, password))

    return username, password


def get_device_config(conn, args):
    """
        get device config
    Args:
        conn: connection to device
        args: command line arguments

    Returns:
        device config: str
    """

    # either we read the device config from a file or we
    # connect to the device and get the running config
    if args.deviceconfig is not None:
        logging.debug("reading config from file args.deviceconfig")
        # read device config from file
        # XXX noch einmal checken ob das geht
        with open(args.deviceconfig, 'r') as f:
            return f.read()
    elif conn is not None:
        """
        read the running config from the device
        we need the username and password.
        """
        logging.debug("getting config")
        return dm.get_config(conn, "running-config")
    else:
        print("problem getting config")
        logging.critical("problem getting config")
        return None


if __name__ == "__main__":

    """
    There is only on mandatory argument. We need the device config or the device.
    The other arguments can override the default values configured
    in our config file.
    """
    parser = argparse.ArgumentParser()
    # what to do
    parser.add_argument('--onboarding', action='store_true')
    parser.add_argument('--interfaces', action='store_true')
    parser.add_argument('--vlans', action='store_true')
    parser.add_argument('--cables', action='store_true')
    parser.add_argument('--config-context', action='store_true')
    parser.add_argument('--backup', action='store_true')
    parser.add_argument('--show-facts', action='store_true')
    parser.add_argument('--show-config', action='store_true')

    # the user can enter a different config file
    parser.add_argument('--config', type=str, required=False)
    # we need the config. The config can be read or retrieved
    # from the device
    parser.add_argument('--deviceconfig', type=str, required=False)
    parser.add_argument('--device', type=str, required=False)
    parser.add_argument('--list', type=str, required=False)
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

    # set logging
    cfg_loglevel = helper.get_value_from_dict(onboarding_config, ['onboarding','logging','level'])
    if cfg_loglevel == 'debug':
        loglevel = logging.DEBUG
    elif cfg_loglevel == 'info':
        loglevel = logging.INFO
    elif cfg_loglevel == 'critical':
        loglevel = logging.CRITICAL
    elif cfg_loglevel == 'error':
        loglevel = logging.ERROR
    elif cfg_loglevel == 'none':
        loglevel = 100
    else:
        loglevel = logging.NOTSET
    log_format = helper.get_value_from_dict(onboarding_config, ['onboarding','logging','format'])
    if log_format is None:
        log_format = '%(asctime)s %(levelname)s:%(message)s'
    logfile = helper.get_value_from_dict(onboarding_config, ['onboarding','logging','filename'])
    logging.basicConfig(level=loglevel,
                        format=log_format,
                        filename=logfile)
    logging.debug("config %s read" % config_file)

    # get default values of prefixes. This is needed only once
    repo = args.repo or onboarding_config['files']['prefixe']['repo']
    filename = args.prefixe or onboarding_config['files']['prefixe']['filename']
    logging.debug("reading %s from %s" % (filename, repo))
    prefixe_str = helper.get_file(onboarding_config["sot"]["api_endpoint"],
                                  repo,
                                  filename)
    if prefixe_str is None:
        logger.error("could not load prefixe.")
        print("could not load prefixe.")
        sys.exit(-1)

    try:
        prefixe_yaml = yaml.safe_load(prefixe_str)
        if prefixe_yaml is not None and 'prefixe' in prefixe_yaml:
            prefixe = prefixe_yaml['prefixe']
    except Exception as exc:
        logger.error("got exception: %s" % exc)
        print("got exception: %s" % exc)
        sys.exit(-1)

    """
    get username and password
    """
    username, password = get_username_and_password(args)

    """
    we have the static values. Now get the config of each device and call
    onboarding.
    """

    # result contains all the results of our onboarding run
    result = defaultdict(dict)
    # devicelist is the list of devices
    devicelist = []
    # conn is the connection to a device
    conn = None

    # add list of devices to our list of devices
    if args.list is not None:
        with open(args.list) as f:
            devicelist = f.read().splitlines()

    # add devices from cli to list
    if args.device is not None:
        devicelist += args.device.split(',')

    # if the user uses args.deviceconfig we read the config
    # instead of adding devices to our list of devices
    # this parameter can only be used with one config, also one device
    if args.deviceconfig is not None:
        # config file specified
        if args.onboarding:
            logging.debug("configfile specified")
            device_config = get_device_config(None, args)
            if device_config is None:
                logger.error("could not read device config")
                print("could not read device config")
                sys.exit(-1)
            device_facts = dm.get_facts()
            result = onboarding(device_facts,
                                device_config,
                                onboarding_config,
                                prefixe)
    else:
        for device in devicelist:
            logging.debug("processing %s" % device)
            # get connection
            conn = dm.open_connection(device,
                                      username,
                                      password,
                                      args.platform,
                                      args.port)
            # retrieve facts like fqdn
            device_facts = dm.get_facts(conn)
            device_facts['args.device'] = device
            # retrieve device config as list of strings
            device_config = get_device_config(conn, args)
            if device_config is None:
                logger.error("could not retrieve device config")
                conn.close()
                continue
            conn.close()

            if args.show_facts:
                print(json.dumps(dict(device_facts), indent=4))
            if args.show_config:
                print(device_config)

            ret = onboarding(device_facts,
                             device_config,
                             onboarding_config,
                             prefixe)
            result.update(ret)

    # after adding all devices to our sot we add the cables
    if args.cables:
        for device in devicelist:
            logging.debug("adding cables of %s to sot" % device)
            conn = dm.open_connection(device,
                                      username,
                                      password,
                                      args.platform,
                                      args.port)
            device_facts = dm.get_facts(conn)
            device_facts['args.device'] = device
            result['cables'] = onboarding_cables(conn, device_facts, onboarding_config)
            conn.close()

    target = helper.get_value_from_dict(onboarding_config,
                                        ['onboarding','logging','result'])
    if target == 'stdout':
        if result:
            print(json.dumps(dict(result), indent=4))
    else:
        with open(target, 'w') as f:
            f.write(json.dumps(dict(result),indent=4))

#
# Todo:
#  - vlan hinzufuegen wenn es noch nicht als vlan im nautobot ist (switch) evtl. mit arg als parameter!
#  - svi hat falschen typ (other, sollte virtual sein)
