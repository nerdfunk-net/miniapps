import yaml
from collections import abc


def readConfig(filename):
    """
    read config from file
    Returns: json
    """
    with open(filename) as f:
        return yaml.safe_load(f.read())
def clean_dict(obj, func):

    """

    Args:
        obj: dict
        func: eg. func = lambda val: val is None

    Returns:
        cleaned dict
    """
    if isinstance(obj, dict):
        # the call to `list` is useless for py2 but makes
        # the code py2/py3 compatible
        for key in list(obj.keys()):
            if func(obj[key]):
                del obj[key]
            else:
                clean_dict(obj[key], func)
    else:
        # neither a dict nor a list, do nothing
        pass

