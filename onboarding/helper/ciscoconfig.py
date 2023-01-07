from ciscoconfparse import CiscoConfParse, IPv4Obj
from netaddr import IPAddress
from collections import defaultdict
import re
import yaml
import json


# this defaultdict enables us to use infinite numbers of arguments
def inf_defaultdict():
    return defaultdict(inf_defaultdict)


MAPPING_YAML = './helper/mapping.yaml'

# define some regular expressions we use later
IPv4_REGEX = r"ip\saddress\s(\S+\s+\S+)"
DHCP = r"ip\saddress\sdhcp"
LAG = r" channel-group\s(\d+)\smode\s(\S+)$"
OSPF_ROUTER_ID = r"^ router-id\s(\S+)"
HOSTNAME = r"^hostname\s+(\S+)"
DOMAIN_NAME = r"^ip\s+domain\s+name\s+(\S+)"
CHANNEL_GROUP = r"^ channel-group"
VLAN_NAME = r"^ name (\S+)"
ACCESS = r"^ switchport mode access"
TRUNK = r"^ switchport mode trunk"
SWITCHPORT_ACCESS_VLAN = r"^ switchport access vlan (\d+)"
TRUNK_ALLOWED_VLANS = r"^ switchport trunk allowed vlan (\S+)"

# the next regexes result in true or false
# use the onboarding config to add other tags to the sot
# eg. OSPF and DHCP tags are set using this config
REGEXES = {'no_switchport': r"^ no switchport",
           'shutdown': r"^ shutdown",
           'access': r"^ switchpport mode access",
           }


class DeviceConfig:
    # raw is our config
    __raw = ""
    # config is the parsed cisco config
    __deviceConfig = []
    # config is our finished config dict that includes all necessary values to
    # add the device and the interface to our sot
    __config = inf_defaultdict()
    # the mapping includes the interface mapping eg. GigabitEther to 1000base-t
    __mapping = None
    # the list of vlans includes all vlans configured on an interface (switch access vlan xyz)
    __list_of_vlans = None

    def __init__(self):
        self.__config = inf_defaultdict()
        self.read_mapping(MAPPING_YAML)

    def __init__(self, raw):
        self.__raw = raw
        self.__config = inf_defaultdict()
        self.read_mapping(MAPPING_YAML)
        # get config from ciscoconfparse
        self.__deviceConfig = CiscoConfParse(self.__raw)
        # parse config and add values
        self.__parse_config()

    def read_mapping(self, filename):
        with open(filename) as f:
            self.__mapping = yaml.safe_load(f.read())

    def __parse_config(self):
        """
        builds the dict we use to add the device to our sot

        Returns:

        """

        # a set of vlans we find on this device
        self.__list_of_vlans = set()

        # get hostname
        self.__config["hostname"] = self.__deviceConfig.re_match_iter_typed(HOSTNAME, default='')
        # get domain name
        self.__config["domain"] = self.__deviceConfig.re_match_iter_typed(DOMAIN_NAME, default='')
        self.__config["fqdn"] = "%s.%s" % (self.__config["hostname"], self.__config["domain"])

        # parse vlans
        vlan_cfgs = self.__deviceConfig.find_objects(r"^vlan")
        for vlan_cfg in vlan_cfgs:
            vid = vlan_cfg.text[len("vlan "):]
            name = vlan_cfg.re_match_iter_typed(VLAN_NAME, default='')
            self.__config["vlan"][vid]['vid'] = vid
            self.__config["vlan"][vid]['name'] = name
            self.__list_of_vlans.add(vid)

        """
         we process the config in the following order:
         - set name
         - get description
         - get interface type
         - get port-channel
         - get switchports
         - get vlans
         - get trunks
         - process regular expressions
         - get ip addresses
         - check if ospf is configured
        """
        interface_cmds = self.__deviceConfig.find_objects(r"^interface ")
        for interface_cmd in interface_cmds:
            intf_name = interface_cmd.text[len("interface "):]
            self.__config["interfaces"][intf_name]["name"] = intf_name
            self.__config["interfaces"][intf_name]["description"] = "not set"
            self.__config["interfaces"][intf_name]["type"] = self.get_interface_type(intf_name.lower())

            # get description
            for cmd in interface_cmd.re_search_children(r"^ description "):
                self.__config["interfaces"][intf_name]["description"] = cmd.text.strip()[len("description "):]

            # check if port-channel
            for cmd in interface_cmd.re_search_children(CHANNEL_GROUP):
                match = re.match(LAG, cmd.text)
                if match:
                    self.__config["interfaces"][intf_name].update({
                        "lag": {
                            "group": match.group(1),
                            "mode": match.group(2)
                        }
                    })

            # check switchport
            for cmd in interface_cmd.re_search_children(ACCESS):
                match = re.match(ACCESS, cmd.text)
                if match:
                    self.__config["interfaces"][intf_name]["switchport"]["mode"] = "access"
                    # a valid (but very ugly) cisco config ist to configure the interface
                    # a switchport but not use the any vlans (no switchport access vlan x)
                    # we init the switchport and set the vlan_id = 1 (the default vlan)
                    self.__config["interfaces"][intf_name]["switchport"]["vlan"] = 1
                    self.__list_of_vlans.add("1")

            # check access VLAN
            for cmd in interface_cmd.re_search_children(SWITCHPORT_ACCESS_VLAN):
                match = re.match(SWITCHPORT_ACCESS_VLAN, cmd.text)
                if match:
                    if 'vlan' not in self.__config["interfaces"][intf_name]['switchport']:
                        self.__config["interfaces"][intf_name]['switchport']['vlan'] = []
                    self.__config["interfaces"][intf_name]['switchport']["vlan"] = match.group(1)
                    self.__list_of_vlans.add(match.group(1))

            # check TRUNK
            for cmd in interface_cmd.re_search_children(TRUNK):
                match = re.match(TRUNK, cmd.text)
                if match:
                    if 'switchport' not in self.__config["interfaces"][intf_name]:
                        self.__config["interfaces"][intf_name]['switchport']['mode'] = "tagged"

            # check if TRUNK has allowed vlans configured
            for cmd in interface_cmd.re_search_children(TRUNK_ALLOWED_VLANS):
                match = re.match(TRUNK_ALLOWED_VLANS, cmd.text)
                if match:
                    if 'vlan' not in self.__config["interfaces"][intf_name]['switchport']:
                        self.__config["interfaces"][intf_name]['switchport']['vlan'] = []
                    vlans = match.group(1)
                    if '-' in vlans:
                        self.__config["interfaces"][intf_name]['switchport']['range'] = True
                    else:
                        for i in vlans.split(','):
                            self.__config["interfaces"][intf_name]['switchport']["vlan"].append(i)

            # check all defined regexes
            for regex in REGEXES:
                for r in interface_cmd.re_search_children(REGEXES[regex]):
                    self.__config["interfaces"][intf_name][regex] = True

            # get IP Adresses
            for cmd in interface_cmd.re_search_children(IPv4_REGEX):
                ipv4_addr = interface_cmd.re_match_iter_typed(IPv4_REGEX, result_type=IPv4Obj)
                self.__config["interfaces"][intf_name].update({
                    "ipv4": {
                        "address": ipv4_addr.ip.exploded,
                        "netmask": ipv4_addr.netmask.exploded,
                        "cidr": "%s/%s" % (
                            ipv4_addr.ip.exploded,
                            IPAddress(ipv4_addr.netmask.exploded).netmask_bits()
                        ),
                        "bits": IPAddress(ipv4_addr.netmask.exploded).netmask_bits(),
                    }
                })

        """
        check if config contains OSPF 
        """
        for ospf_cmds in self.__deviceConfig.find_objects(r"^router ospf"):
            ospf_process = re.match(r'router ospf\s(\d+)', ospf_cmds.text).group(1)
            if ospf_process is not None:
                self.__config["ospf"][ospf_process]['config'] = []
                for val_obj in ospf_cmds.children:
                    self.__config["ospf"][ospf_process]['config'].append(val_obj.text)
                    rid = val_obj.re_match_typed(OSPF_ROUTER_ID, default='None')
                    if rid != 'None':
                        self.__config["ospf"][ospf_process]['rid'] = rid

        # print(json.dumps(self.__config["ospf"], indent=4))
        # print(json.dumps(self.__config,indent=4))

    def get_hostname(self):
        return self.__config["hostname"]

    def get_fqdn(self):
        return self.__config["fqdn"]

    def get_ipaddress(self, interface, result='cidr'):
        if interface not in self.__config["interfaces"]:
            return None
        if 'ipv4' not in self.__config["interfaces"][interface]:
            return None
        if result == 'cidr':
            if 'cidr' in self.__config["interfaces"][interface]['ipv4']:
                return self.__config["interfaces"][interface]['ipv4']['cidr']
            else:
                return None
        if result == 'ip':
            if 'address' in self.__config["interfaces"][interface]['ipv4']:
                return self.__config["interfaces"][interface]['ipv4']['address']
            else:
                return None

        return self.__config["interfaces"][interface]

    def get_netmask(self, interface, result='ip'):
        if interface not in self.__config["interfaces"]:
            return None
        if result == 'cidr':
            return self.__config["interfaces"][interface]['ipv4']['bits']

        return self.__config["interfaces"][interface]['ipv4']['netmask']

    def get_ospf_processes(self):
        processes = []
        if self.__config['ospf']:
            for process in self.__config['ospf']:
                processes.append(process)
        return processes

    def get_ospf_config(self, process):
        if process in self.__config['ospf']:
            return self.__config['ospf'][process]['config']
        else:
            return None

    def tag_interfaces(self, tag, regex):
        interface_cmds = self.__deviceConfig.find_objects(r"^interface ")
        for interface_cmd in interface_cmds:
            intf_name = interface_cmd.text[len("interface "):]
            for cmd in interface_cmd.re_search_children(regex):
                match = re.match(regex, cmd.text)
                if match:
                    if 'tags' not in self.__config["interfaces"][intf_name]:
                        self.__config["interfaces"][intf_name]["tags"] = []
                    self.__config["interfaces"][intf_name]["tags"].append(tag)

    def get_interface_type(self, interface):
        for mapping in self.__mapping['interfaces']:
            if mapping.lower() in interface:
                return self.__mapping['interfaces'][mapping]
        return self.__mapping['interfaces']['default']

    def get_interface(self, interface):
        if interface in self.__config["interfaces"]:
            return self.__config["interfaces"][interface]
        return None

    def get_interface_name_by_address(self, ip):
        for intf_name in self.__config["interfaces"]:
            if 'ipv4' in self.__config["interfaces"][intf_name]:
                if 'address' in self.__config["interfaces"][intf_name]['ipv4']:
                    if self.__config["interfaces"][intf_name]['ipv4']['address'] == ip:
                        return intf_name
        return None

    def get_interfaces(self):
        return self.__config["interfaces"]

    def get_vlans(self):
        return self.__config["vlan"], list(self.__list_of_vlans)

    def get_section(self, section):
        return self.__deviceConfig.find_all_children(r"^%s" % section)

