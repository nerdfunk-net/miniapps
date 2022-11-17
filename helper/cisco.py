from ciscoconfparse import CiscoConfParse, IPv4Obj
from netaddr import IPAddress
import re
import json

class DeviceConfig:
    __raw = ""
    __deviceConfig = None
    __config = {}

    def __init__(self, filename):
        self.read_config(filename)
        self.__init_config()

    def read_config(self, filename):
        # read device config
        with open(filename, 'r') as file:
            self.__raw = file.read().splitlines()

    def __init_config(self):
        self.__deviceConfig = CiscoConfParse(self.__raw)
        self.__parse_config()

    def __parse_config(self):
        IPv4_REGEX = r"ip\saddress\s(\S+\s+\S+)"
        PO_ACTIVE = r" channel-group\s(\d+)\smode\s(\S+)$"

        self.__config["interfaces"] = {}
        interface_cmds = self.__deviceConfig.find_objects(r"^interface ")
        for interface_cmd in interface_cmds:
            intf_name = interface_cmd.text[len("interface "):]
            self.__config["interfaces"][intf_name] = {}
            self.__config["interfaces"][intf_name]["description"] = "not set"

            # get description
            for cmd in interface_cmd.re_search_children(r"^ description "):
                self.__config["interfaces"][intf_name]["description"] = cmd.text.strip()[len("description "):]

            # check if LACP port-channel
            for cmd in interface_cmd.re_search_children(r"^ channel-group"):
                match = re.match(PO_ACTIVE, cmd.text)
                if match:
                    self.__config["interfaces"][intf_name]["po"] = {}
                    self.__config["interfaces"][intf_name].update({
                        "po": {
                            "group": match.group(1),
                            "mode": match.group(2)
                        }
                    })

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
                        "bits": IPAddress(ipv4_addr.netmask.exploded).netmask_bits()
                    }
                })
        print (json.dumps(self.__config,indent=4))

    def get_hostname(self):
        return (self.__deviceConfig.re_match_iter_typed(r'^hostname\s+(\S+)', default=''))