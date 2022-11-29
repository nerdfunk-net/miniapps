#!/usr/bin/env python

import argparse
import json
import sys

import yaml
from helper.sot import get_file, send_request
from helper.config import read_config

# set default config file to your needs
default_config_file = "./config.yaml"


def get_defaults(repo, filename):
    """
    get default values from sot

    Args:
        repo:
        filename:

    Returns:

    """

    defaults_str = get_file(config["sot"]["api_endpoint"],
                            repo,
                            filename)
    if defaults_str is None:
        print("%s %s does not exists or could not be read" % (repo, filename))
        return None

    # convert defaults to dict
    try:
        defaults = yaml.safe_load(defaults_str)
    except Exception as exc:
        print("got exception: %s" % exc)
        return None

    return defaults


def origin_git(config, update=False):
    sites = []
    manufacturers = []
    roles = []
    devicetypes = []
    platforms = []

    # we use a dict to store our results
    result = {'logs': [], 'success': []}

    repo = config['files']['sites']['repo']
    filename = config['files']['sites']['filename']

    # get default values from repo
    defaults = get_defaults(repo, filename)
    if defaults is None:
        print("could not read default values from %s/%s" % (repo, filename))
        return None

    # get sites, manufacturer and so on from default file
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

    # check if we use some sites that are not configured
    not_found = []
    for a in sites:
        found = False
        for b in defaults['sites']:
            if a == b['name']:
                found = True
        if not found:
            not_found.append(a)

    if not_found:
        print ("the following sites are not part of your default config!!!")
        for site in set(not_found):
            print(site)
        print ("Please correct your default config")

    for site in defaults['sites']:
        data = {'name': site['name'],
                'slug': site['slug'],
                'status': site['status']
                }
        # send request to add site to nautobot
        suc = send_request('addsite',
                           config["sot"]["api_endpoint"],
                           data,
                           result,
                           'site',
                           'site added')

        # check if site already exists
        # if so we update only if user set update to True
        if not suc and update:
            update_data = {}
            update_list = ['asn', 'time_zone', 'description', 'physical_address',
                           'shipping_address', 'latitude', 'longitude', 'contact_name',
                           'contact_phone', 'contact_email', 'comments']
            for u in update_list:
                if u in site:
                    update_data[update] = site[u]

            send_request('updatesite',
                         config["sot"]["api_endpoint"],
                         {'slug': site['slug'], 'config': update_data},
                         result,
                         'site',
                         '%s updated' % site['slug'])

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

    # add platform
    for p in defaults['platforms']:
        if 'napalm_driver' in p:
            driver = p['napalm_driver']
        else:
            driver = ""

        data = {'name': p['name'],
                'slug': p['slug'],
                'napalm_driver': driver
                }
        suc = send_request('addplatform',
                           config["sot"]["api_endpoint"],
                           data,
                           result,
                           'platform',
                           '%s added' % p['name'])

        if not suc and args.update:
            update_data = {}
            update_list = ['slug', 'name', 'manufacturer', 'description', 'napalm_driver', 'napalm_args']
            for update in update_list:
                if update in p:
                    update_data[update] = p[update]
            send_request('updateplatform',
                         config["sot"]["api_endpoint"],
                         {'slug': p['slug'], 'config': update_data},
                         result,
                         'platform',
                         '%s updated' % p['slug'])

    print(json.dumps(result, indent=4))


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('--origin', type=str, required=True)
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

    if args.repo:
        config['files']['sites']['repo'] = args.repo
    if args.filename:
        config['files']['sites']['filename'] = args.filename

    if args.origin == 'git':
        origin_git(config, args.update)
