import logging
import yaml
from helper import helper


def ospf(device_context, ospf_routing, dfl_ospf):

    for conf in dfl_ospf:
        logging.info("checking OSPF config %s" % conf)
        # parse each line and check if our config is part of dfl
        diff = []
        for line in ospf_routing:
            # some lines have a leading space at the beginning
            stripped = line.strip()
            if stripped not in dfl_ospf[conf]:
                diff.append(stripped)

        device_context['ospf'] = diff


def to_sot(result, device_fqdn, device_context, ciscoconf, onboarding_config):
    """
        write routing information of a device to its config_context
    Args:
        result:
        device_fqdn:
        device_context:
        ciscoconf:
        onboarding_config:

    Returns:

    """

    """
    we have three parts to be considered here:
      - static routing
      - OSFP
      - BGP
    """
    default_config_str = helper.get_file(onboarding_config["sot"]["api_endpoint"],
                                         "default_device_config",
                                         "device_config.yaml")

    if default_config_str is None:
        logging.info("no default config found")
        default_config_str = []

    try:
        defaults = yaml.safe_load(default_config_str)
    except Exception as exc:
        logging.error("could not parse device_config.yaml")
        default = {}

    # 1. OSPF
    ospf_routing = ciscoconf.get_section("router ospf")
    dfl_ospf = defaults.get('ospf_routing')
    if dfl_ospf is None:
        logging.info("no default OSPF config found")
    else:
        ospf(device_context, ospf_routing, dfl_ospf)

