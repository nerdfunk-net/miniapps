#!/usr/bin/env python

import argparse
import json
import sys

import yaml
from helper.sot import get_file, send_request
from helper.config import read_config

# set default config file to your needs
default_config_file = "./config.yaml"


def add_defaults_to_sot():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, required=False)
    parser.add_argument('--repo', type=str, required=False)
    parser.add_argument('--filename', type=str, required=False)
    parser.add_argument('--update', type=bool, required=False, default=False)

    args = parser.parse_args()

    # read config
    if args.config is not None:
        config_file = args.config
    else:
        config_file = default_config_file
    config = read_config(config_file)

    # get default values from sot
    repo = args.repo or config['files']['sites']['repo']
    filename = args.filename or config['files']['sites']['filename']
    defaults_str = get_file(config["sot"]["api_endpoint"],
                            repo,
                            filename)
    if defaults_str is None:
        print("%s %s does not exists or could not be read" % (repo, filename))
        sys.exit(-1)

    # add sites to sot
    sites = []
    manufacturers = []
    roles = []
    devicetypes = []
    platforms = []

    # convert defaults to dict
    try:
        defaults = yaml.safe_load(defaults_str)
    except Exception as exc:
        print("got exception: %s" % exc)

    # the sites contain the following values:
    # - manufacturer

    if 'prefixe' in defaults:
        for prefixe in defaults['prefixe']:
            if 'site' in defaults['prefixe'][prefixe]:
                sites.append(defaults['prefixe'][prefixe]['site'])
            if 'manufacturer' in defaults['prefixe'][prefixe]:
                manufacturers.append(defaults['prefixe'][prefixe]['manufacturer'])
            if 'role' in defaults['prefixe'][prefixe]:
                roles.append(defaults['prefixe'][prefixe]['role'])
            if 'devicetype' in defaults['prefixe'][prefixe]:
                devicetypes.append(defaults['prefixe'][prefixe]['devicetype'])
            if 'platform' in defaults['prefixe'][prefixe]:
                platforms.append(defaults['prefixe'][prefixe]['platform'])

    # we use a dict to store our results
    result = {}
    result['logs'] = []
    result['success'] = []

    # check if we use some sites that are not configured
    for a in sites:
        found = False
        for b in defaults['sites']:
            if a == b['name']:
                found = True
        if not found:
            print ("site %s is used but not configured" % a)

    for s in defaults['sites']:
        data = {'name': s['name'],
                'slug': s['slug'],
                'status': s['status']
                }
        suc = send_request('addsite',
                     config["sot"]["api_endpoint"],
                     data,
                     result,
                     'site',
                     'site added')

        # check if site already exists
        # if so we update only if user set update to True
        if not suc and args.update:
            update_data = {}
            update_list = ['asn', 'time_zone', 'description', 'physical_address',
                           'shipping_address', 'latitude', 'longitude', 'contact_name',
                           'contact_phone', 'contact_email', 'comments']
            for update in update_list:
                if update in s:
                    update_data[update] = s[update]

            send_request('updatesite',
                         config["sot"]["api_endpoint"],
                         {'slug': s['slug'], 'config': update_data},
                         result,
                         'site',
                         '%s updated' % s['slug'])

    # add manufacturers
    for m in defaults['manufacturers']:
        data = {'name': m['name'],
                'slug': m['slug']}
        suc = send_request('addmanufacturer',
                     config["sot"]["api_endpoint"],
                     data,
                     result,
                     'manufacturer',
                     'manufacturer added')

        if not suc and args.update:
            update_data = {}
            update_list = ['slug', 'name', 'description']
            for update in update_list:
                if update in m:
                    update_data[update] = m[update]
            send_request('updatemanufacturer',
                         config["sot"]["api_endpoint"],
                         {'slug': m['slug'], 'config': update_data},
                         result,
                         'manufacturer',
                         '%s updated' % m['slug'])

    print(json.dumps(result, indent=4))


if __name__ == "__main__":
    add_defaults_to_sot()
