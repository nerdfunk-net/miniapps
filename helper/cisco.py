from ciscoconfparse import CiscoConfParse, IPv4Obj
from netaddr import IPAddress
import re
import json

class DeviceConfig:
    __raw = ""
    __deviceConfig = []
    __confige = None

    def __init__(self, filename):
        self.__config = {}
        self.read_config(filename)
        self.init_config()

    def read_config(self, filename):
        # read device config
        with open(filename, 'r') as file:
            self.__raw = file.read().splitlines()

    def init_config(self):
        self.__deviceConfig = CiscoConfParse(self.__raw)
        self.__parse_config()

    def get_config(self):
        return self.__config

    def __parse_config(self):
        IPv4_REGEX = r"ip\saddress\s(\S+\s+\S+)"
        PO_ACTIVE = r" channel-group\s(\d+)\smode\s(\S+)$"
        OSPF_ROUTER_ID = r"^ router-id\s(\S+)"
        HOSTNAME = r"^hostname\s+(\S+)"
        CHANNEL_GROUP = r"^ channel-group"
        VLAN = r"^ switchport access vlan (\d+)"

        # these regexes results in true or false
        regexes = {}
        regexes['no_switchport'] = r"^ no switchport"
        regexes['switchport'] = r"^ switchport"
        regexes['shutdown'] = r"^ shutdown"
        regexes['trunk'] = r"^ switchport mode trunk"
        regexes['access'] = r"^ switchpport mode access"

        """
        get hostname
        """
        self.__config["hostname"] = self.__deviceConfig.re_match_iter_typed(HOSTNAME, default='')

        """
        parse interface config first
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
                match = re.match(PO_ACTIVE, cmd.text)
                if match:
                    self.__config["interfaces"][intf_name]["po"] = {}
                    self.__config["interfaces"][intf_name].update({
                        "po": {
                            "group": match.group(1),
                            "mode": match.group(2)
                        }
                    })

            # check VLAN
            for cmd in interface_cmd.re_search_children(VLAN):
                match = re.match(VLAN, cmd.text)
                if match:
                    self.__config["interfaces"][intf_name]["vlan"] = match.group(1)

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
        if type == 'cidr':
            return self.__config["interfaces"][interface]['ipv4']['cidr']
        if type== 'ip':
            return self.__config["interfaces"][interface]['ipv4']['address']

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
            if 'tags' not in self.__config["interfaces"][intf_name]:
                self.__config["interfaces"][intf_name]["tags"] = []
            for cmd in interface_cmd.re_search_children(regex):
                match = re.match(regex, cmd.text)
                if match:
                    self.__config["interfaces"][intf_name]["tags"].append(tag)

    def get_interface_type(self, interface):
        if 'Loopback' in interface:
            return 'virtual'
        if 'GigabitEthernet' in interface:
            return 'A_1000BASE_T'
        if 'Portchannel' in interface:
            return 'LAG'
        if 'TenGigabit' in interface:
            return 'A_10GBASE_T'
        return 'OTHER'

    def get_interface(self, interface):
        if interface in self.__config["interfaces"]:
            return self.__config["interfaces"][interface]
        return None