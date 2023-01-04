import logging
from helper import helper


def device(result, device_fqdn, raw_device_config, onboarding_config):
    """

    Args:
        result:
        device_fqdn:
        raw_device_config:
        onboarding_config:

    Returns:


    new_config = {"tags": "test"}

    data_set_primary = {
        "name": device_fqdn,
        "config": new_config
    }

    logging.debug("adding userdefined tags of %s to sot" % device_fqdn)
    result[device_fqdn]['user_based_device_tags'] = helper.send_request("updatedevice",
                                                                        onboarding_config["sot"]["api_endpoint"],
                                                                        data_set_primary)
    """

    # write everything you need to "log" to result afterwards
    result[device_fqdn]['userbased_device'] = "nothing done"
