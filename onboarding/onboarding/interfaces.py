import logging
from businesslogic import your_interfaces as user_int
from helper import helper


def to_sot(result, args, device_fqdn, primary_defaults, ciscoconf, onboarding_config):

    """
    loop through all interfaces and update/add item to sot

    Args:
        result:
        args:
        device_fqdn:
        primary_defaults:
        ciscoconf:
        onboarding_config:

    Returns:

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
            "config": {
                "interface": name,
                "interface_type": interface['type'],
                "enabled": enabled,
                "description": interface['description']
            }
        }
        logging.debug("adding %s / %s to sot" % (device_fqdn, name))
        result[device_fqdn][name] = helper.send_request("interface",
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
            lag_data = {"lag": "Port-channel%s" % interface["lag"]["group"]}
            newconfig = {
                "name": device_fqdn,
                "interface": name,
                "config": lag_data
            }
            logging.debug("adding etherchannels of %s to sot" % device_fqdn)
            result[device_fqdn][name]['portchannel'] = helper.send_request("updateinterface",
                                                                           onboarding_config["sot"]["api_endpoint"],
                                                                           newconfig)
        # setting switchport or trunk
        if 'switchport' in interface:
            mode = interface['switchport']['mode']
            data = {}
            if mode == 'access':
                data = {"mode": "access",
                        "untagged": interface['switchport']['vlan'],
                        "site": args.site or primary_defaults['site']
                        }
            elif mode == 'tagged':
                # this port is either a trunked with allowed vlans (mode: tagged)
                # or a trunk with all vlans mode: tagged-all
                # check if we have allowed vlans
                if 'vlan' in interface['switchport'] and \
                        'range' not in interface['switchport']:
                    vlans = ",".join(interface['switchport']['vlan'])
                    data = {"mode": "tagged",
                            "tagged": vlans,
                            "site": args.site or primary_defaults['site']
                            }
                else:
                    data = {"mode": "tagged-all",
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

        # call the user defined business logic
        # the user defined bl can overwrite and modify the device_context
        logging.debug("calling business logic for %s/%s" % (device_fqdn, name))
        user_int.interface_tags(result,
                                device_fqdn,
                                name,
                                ciscoconf.get_section("interface %s" % name),
                                onboarding_config)


def vlans(result, device_fqdn, args, ciscoconf, primary_defaults, onboarding_config):

    # add vlans
    vlans,set_of_vlans = ciscoconf.get_vlans()
    added_vlans = {}

    for vid in vlans:
        data_add_vlan = {
            "vid": vid,
            "name": vlans[vid]['name'],
            "status": "active",
            "site": args.site or primary_defaults['site']
        }
        logging.debug("adding vlan %s of %s to sot" % (vid, device_fqdn))
        result[device_fqdn]['vlan'][vid] = helper.send_request("addvlan",
                                                               onboarding_config["sot"]["api_endpoint"],
                                                               data_add_vlan)
        # create list of vlans added to the sot
        if result[device_fqdn]['vlan'][vid]['success']:
            added_vlans[vid] = True

    # now add all vlans of the set that were not added to the sot before
    for vid in set_of_vlans:
        if vid not in added_vlans:
            data_add_vlan = {
                "vid": vid,
                "name": "unknown vlan %s" % vid,
                "status": "active",
                "site": args.site or primary_defaults['site']
            }
            logging.debug("adding vlan %s of %s to sot" % (vid, device_fqdn))
            result[device_fqdn]['vlan'][vid] = helper.send_request("addvlan",
                                                                   onboarding_config["sot"]["api_endpoint"],
                                                                   data_add_vlan)

