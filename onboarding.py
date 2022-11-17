#!/usr/bin/env python

import argparse
from helper.config import readConfig
from helper.cisco import DeviceConfig


# set default config file to your needs
default_config_file = "./config.yaml"


def onboarding():

    parser = argparse.ArgumentParser()
    parser.add_argument('--deviceconfig', type=str, required=True)
    parser.add_argument('--config', type=str, required=False)

    args = parser.parse_args()

    # read config
    if args.config is not None:
        config_file = args.config
    else:
        config_file = default_config_file
    config = readConfig(config_file)

    """
    what do we need?
    
    - device name
    - primary interface w/ ip address
    
    """

    ciscoconf = DeviceConfig(args.deviceconfig)


if __name__ == "__main__":
    onboarding()