from ciscoconfparse import CiscoConfParse, IPv4Obj
from netaddr import IPAddress
from operator import add
import re
import yaml
import json


MAPPING_YAML = './helper/mapping.yaml'

class DeviceConfig:
    __raw = ""
    __deviceConfig = []
    __config = None
    __mapping = None

    def __init__(self, filename):
        self.__config = {}
        self.read_config(filename)
        self.get_mapping(MAPPING_YAML)
        self.init_config()

    def read_config(self, filename):
        # read device config
        with open(filename, 'r') as file:
            self.__raw = file.read().splitlines()

    def get_mapping(self, filename):
        with open(filename) as f:
            self.__mapping = yaml.safe_load(f.read())
    def init_config(self):
        self.__deviceConfig = CiscoConfParse(self.__raw)
        self.__parse_config()

    def get_config(self):
        return self.__config

    def __parse_config(self):
        IPv4_REGEX = r"ip\saddress\s(\S+\s+\S+)"
        LAG = r" channel-group\s(\d+)\smode\s(\S+)$"
        OSPF_ROUTER_ID = r"^ router-id\s(\S+)"
        HOSTNAME = r"^hostname\s+(\S+)"
        CHANNEL_GROUP = r"^ channel-group"
        VLAN_NAME = r"^ name (\S+)"
        ACCESS = r"^ switchport mode access"
        TRUNK = r"^ switchport mode trunk"
        SWITCHPORT_VLAN = r"^ switchport access vlan (\d+)"
        TRUNK_VLANS = r"^ switchport trunk allowed vlan (\S+)"

        # these regexes results in true or false
        regexes = {}
        regexes['no_switchport'] = r"^ no switchport"
        regexes['shutdown'] = r"^ shutdown"
        regexes['access'] = r"^ switchpport mode access"

        """
        get hostname
        """
        self.__config["hostname"] = self.__deviceConfig.re_match_iter_typed(HOSTNAME, default='')

        """
        parse vlans
        """
        self.__config["vlan"] = {}
        vlan_cfgs = self.__deviceConfig.find_objects(r"^vlan")
        for vlan_cfg in vlan_cfgs:
            vid = vlan_cfg.text[len("vlan "):]
            name = vlan_cfg.re_match_iter_typed(VLAN_NAME, default='')
            self.__config["vlan"][vid] = {}
            self.__config["vlan"][vid]['vid'] = vid
            self.__config["vlan"][vid]['name'] = name

        """
        parse interface config first
         - set name
         - get description
         - check if port-channel
         - get IP address
        """
        self.__config["interfaces"] = {}
        interface_cmds = self.__deviceConfig.find_objects(r"^interface ")
        for interface_cmd in interface_cmds:
            intf_name = interface_cmd.text[len("interface "):]
            self.__config["interfaces"][intf_name] = {}
            self.__config["interfaces"][intf_name]['name'] = intf_name
            self.__config["interfaces"][intf_name]["description"] = "not set"

            # get description and interface type
            for cmd in interface_cmd.re_search_children(r"^ description "):
                self.__config["interfaces"][intf_name]["description"] = cmd.text.strip()[len("description "):]
                self.__config["interfaces"][intf_name]['type'] = self.get_interface_type(intf_name)

            # check if port-channel
            for cmd in interface_cmd.re_search_children(CHANNEL_GROUP):
                match = re.match(LAG, cmd.text)
                if match:
                    self.__config["interfaces"][intf_name]["lag"] = {}
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
                    self.__config["interfaces"][intf_name]['switchport'] = {}
                    self.__config["interfaces"][intf_name]['switchport']['mode'] = 'access'

            # check access VLAN
            for cmd in interface_cmd.re_search_children(SWITCHPORT_VLAN):
                match = re.match(SWITCHPORT_VLAN, cmd.text)
                if match:
                    if 'vlan' not in self.__config["interfaces"][intf_name]['switchport']:
                        self.__config["interfaces"][intf_name]['switchport']['vlan'] = []
                    self.__config["interfaces"][intf_name]['switchport']["vlan"] = match.group(1)

            # check TRUNK
            for cmd in interface_cmd.re_search_children(TRUNK):
                match = re.match(TRUNK, cmd.text)
                if match:
                    if 'switchport' not in self.__config["interfaces"][intf_name]:
                        self.__config["interfaces"][intf_name]['switchport'] = {}
                        self.__config["interfaces"][intf_name]['switchport']['mode'] = "tagged"

            # check if TRUNK has allowed vlans configured
            for cmd in interface_cmd.re_search_children(TRUNK_VLANS):
                match = re.match(TRUNK_VLANS, cmd.text)
                if match:
                    if 'vlan' not in self.__config["interfaces"][intf_name]['switchport']:
                        self.__config["interfaces"][intf_name]['switchport']['vlan'] = []
                    vlans = match.group(1)
                    if '-' in vlans:
                        self.__config["interfaces"][intf_name]['switchport']['range'] = True
                    else:
                        for i in vlans.split(','):
                            self.__config["interfaces"][intf_name]['switchport']["vlan"].append(i)                        #self.__config["interfaces"][intf_name]["vlan"]['vlans'].append(vlans.split(','))

            # check all defined regexes
            for regex in regexes:
                for r in interface_cmd.re_search_children(regexes[regex]):
                    self.__config["interfaces"][intf_name][regex] = True

            # get IP Adresses
            for cmd in interface_cmd.re_search_children(IPv4_REGEX):
                ipv4_addr = interface_cmd.re_match_iter_typed(IPv4_REGEX, result_type=IPv4Obj)
                self.__config["interfaces"][intf_name]["ipv4"] = {}
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
        self.__config["ospf"] = {}
        for ospf_cmds in self.__deviceConfig.find_objects(r"^router ospf"):
            ospf_process = re.match(r'router ospf\s(\d+)', ospf_cmds.text).group(1)
            if ospf_process is not None:
                self.__config["ospf"][ospf_process] = {}
                self.__config["ospf"][ospf_process]['config'] = []
                for val_obj in ospf_cmds.children:
                    self.__config["ospf"][ospf_process]['config'].append (val_obj.text)
                    rid = val_obj.re_match_typed(OSPF_ROUTER_ID, default='None')
                    if rid !=  'None':
                        self.__config["ospf"][ospf_process]['rid'] = rid

        #print (json.dumps(self.__config["ospf"], indent=4))
        #print (json.dumps(self.__config,indent=4))

    def get_hostname(self):
        return (self.__config["hostname"])

    def get_ipaddress(self, interface, type='cidr'):
        if interface not in self.__config["interfaces"]:
            return None
        if 'ipv4' not in self.__config["interfaces"][interface]:
            return None
        if type == 'cidr':
            if 'cidr' in self.__config["interfaces"][interface]['ipv4']:
                return self.__config["interfaces"][interface]['ipv4']['cidr']
            else:
                return None
        if type== 'ip':
            if 'address' in self.__config["interfaces"][interface]['ipv4']:
                return self.__config["interfaces"][interface]['ipv4']['address']
            else:
                return None

        return self.__config["interfaces"][interface]

    def get_netmask(self, interface, type='ip'):
        if interface not in self.__config["interfaces"]:
            return None
        if type == 'cidr':
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
            if mapping in interface:
                return self.__mapping['interfaces'][mapping]
        return self.__mapping['interfaces']['default']

    def get_interface(self, interface):
        if interface in self.__config["interfaces"]:
            return self.__config["interfaces"][interface]
        return None

    def get_interfaces(self):
        return self.__config["interfaces"]

    def get_vlans(self):
        return self.__config["vlan"]