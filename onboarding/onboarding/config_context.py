import yaml
import logging
from collections import defaultdict
from helper import helper
from businesslogic import your_config_context as user_cc
from businesslogic import std_routing


def to_sot(result, device_fqdn, ciscoconf, raw_device_config, onboarding_config):

    cfg_contexts = helper.get_value_from_dict(onboarding_config,['onboarding','config_context'])
    device_context = defaultdict(dict)

    # check if we have some config_context rules configured
    if cfg_contexts is None:
        result[device_fqdn]['config_context'] = "no config context configured in config"
        return

    for cfg_context in cfg_contexts:
        for section in cfg_contexts[cfg_context]:
            device_context[cfg_context] = ciscoconf.get_section(section)

    # call the "standard" business logic first
    response = std_routing.to_sot(result,
                                  device_fqdn,
                                  device_context,
                                  ciscoconf,
                                  onboarding_config)

    print(dict(device_context))

    # call the user defined business logic
    # the user defined bl can overwrite and modify the device_context
    response = user_cc.config_context(result,
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
        'subdir': "devices",
        'content': "%s\n%s" % ("---", device_context_yaml),
        'action': 'overwrite',
        'pull': False,
    }

    newconfig = {
        "config": config
    }

    logging.debug("writing config_context to sot")
    result[device_fqdn]['config_context'] = helper.send_request("editfile",
                                                                onboarding_config["sot"]["api_endpoint"],
                                                                newconfig)
