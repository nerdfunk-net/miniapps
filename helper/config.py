import yaml
import pytricia


def read_config(filename):
    """
    read config from file
    Returns: json
    """
    with open(filename) as f:
        return yaml.safe_load(f.read())
def get_prefix_path(config, ip):
    prefix_path = []
    pyt = pytricia.PyTricia()

    # build pytricia tree
    for ip in config:
        pyt.insert(ip, ip)

    prefix = pyt.get(ip)
    prefix_path.append(prefix)

    parent = pyt.parent(prefix)
    while (parent):
        prefix_path.append(parent)
        parent = pyt.parent(parent)
    return prefix_path[::-1]
