import logging
from helper import helper


def interface_tags(result, device_fqdn, interface_name, interface_config, onboarding_config):

    """

    Args:
        result:
        device_fqdn:
        interface_name:
        interface_config:
        onboarding_config:

    Returns:

    """

    """
    
    the interface object can be used to gather more facts of the interface. 
    examples:
    
    get all lines of interface config:
    for line in interface_config:
        do_something_with(line)
    
    # here is an example how to add tags

    logging.debug("adding userdefined tags of %s to sot" % device_fqdn)
    tag_list = "test"

    newconfig = {
        "name": device_fqdn,
        "interface": interface_name,
        "config": {"tags": tag_list}
    }

    if device_fqdn not in result:
        result[device_fqdn] = {}
    if interface_name not in result[device_fqdn]:
        result[device_fqdn][interface_name] = {}

    result[device_fqdn][interface_name]['userbased_interface_tags'] = helper.send_request("updateinterface",
                                                            onboarding_config["sot"]["api_endpoint"],
                                                            newconfig)

    """
