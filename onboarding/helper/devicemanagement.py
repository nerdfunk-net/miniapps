from scrapli import Scrapli
import re


def open_connection(host, username, password, platform, port=22):

    """
        open connection the a device

    Args:
        host:
        username:
        password:
        platform:

    Returns:

    """

    # we have to map the napalm driver to our srapli driver / platform
    #
    # napalm | scrapli
    # -------|------------
    # ios    | cisco_iosxe
    # iosxr  | cisco_iosxr
    # nxos   | cisco_nxos

    mapping = {'ios': 'cisco_iosxe',
               'iosxr': 'cisco_iosxr',
               'nxos': 'cisco_nxos'
               }
    driver = mapping.get(platform)
    if driver is None:
        return None

    device = {
        "host": host,
        "auth_username": username,
        "auth_password": password,
        "auth_strict_key": False,
        "platform": driver,
        "port": port,
        "ssh_config_file": "~/.ssh/ssh_config"
    }

    conn = Scrapli(**device)
    conn.open()

    return conn


def get_config(conn, configtype: str) -> str:
    """
    return config from device

    Args:
        conn:
        configtype:

    Returns:
        config: str
    """

    response = conn.send_command("show %s" % configtype)
    return response.result


def get_facts(conn):
    """
        get a set of facts from the device
    Args:
        conn:

    Returns:
        named dict of facts
    """

    # default values.
    vendor = "Cisco"
    serial_number, fqdn, os_version, hostname, domain_name = ("Unknown",) * 5

    response = conn.send_commands(['show version',
                                   'show hosts'])

    show_ver = response[0].result
    show_hosts = response[1].result

    # this code is from napalm/get_facts
    # uptime/serial_number/IOS version
    for line in show_ver.splitlines():
        if " uptime is " in line:
            hostname, uptime_str = line.split(" uptime is ")
            hostname = hostname.strip()

        if "Processor board ID" in line:
            _, serial_number = line.split("Processor board ID ")
            serial_number = serial_number.strip()

        if re.search(r"Cisco IOS Software", line):
            try:
                _, os_version = line.split("Cisco IOS Software, ")
            except ValueError:
                # Handle 'Cisco IOS Software [Denali],'
                _, os_version = re.split(r"Cisco IOS Software \[.*?\], ", line)
        elif re.search(r"IOS \(tm\).+Software", line):
            _, os_version = line.split("IOS (tm) ")

        os_version = os_version.strip()

    # Determine domain_name and fqdn
    for line in show_hosts.splitlines():
        if "Default domain" in line:
            _, domain_name = line.split("Default domain is ")
            domain_name = domain_name.strip()
            break
    if domain_name != "Unknown" and hostname != "Unknown":
        fqdn = "{}.{}".format(hostname, domain_name)

    # model filter
    try:
        match_model = re.search(
            r"Cisco (.+?) .+bytes of", show_ver, flags=re.IGNORECASE
        )
        model = match_model.group(1)
    except AttributeError:
        model = "Unknown"

    return {
        "vendor": vendor,
        "os_version": str(os_version),
        "serial_number": str(serial_number),
        "model": str(model),
        "hostname": str(hostname),
        "fqdn": fqdn
    }

