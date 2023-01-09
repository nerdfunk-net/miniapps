import logging
from helper import helper


def to_sot(result, conn, device_facts, onboarding_config):

    # get layer2 neighbors
    response = conn.send_command("show cdp neighbors")
    r = response.genie_parse_output()

    for line in r['cdp']['index']:
        device_id = r['cdp']['index'][line]['device_id']
        local_interface = r['cdp']['index'][line]['local_interface']
        port_id = r['cdp']['index'][line]['port_id']
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
        result['cables'][line] = helper.send_request("updateconnection",
                                               onboarding_config["sot"]["api_endpoint"],
                                               newconfig)
