import yaml


def readConfig(filename):
    """
    read config from file
    Returns: json
    """
    with open(filename) as f:
        return yaml.safe_load(f.read())
