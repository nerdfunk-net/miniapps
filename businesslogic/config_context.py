from collections import defaultdict
from helper import helper


def config_context(result, device_fqdn, device_context, raw_device_config, onboarding_config):
    """

    Args:
        result:
        raw_device_config:

    Returns:

    """

    """
    
     config = {
        'repo': 'config_contexts',
        'filename': device_fqdn,
        'content': "%s\n%s" % ("---", device_context_as_yaml),
        'action': 'overwrite',
        'pull': False,
    }

    newconfig = {
        "config": config
    }

    result[device_fqdn]['config_context'] = helper.send_request("editfile",
                                                                onboarding_config["sot"]["api_endpoint"],
                                                                newconfig)
    """

    # write everything you need to "log" to result
    result[device_fqdn]['userbased_config_context'] = "nothing done"

    return device_context