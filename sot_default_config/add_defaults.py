#!/usr/bin/env python

import argparse
import json
import yaml
from helper import helper

# set default config file to your needs
default_config_file = "./config.yaml"


def get_defaults(repo, filename, update=False):
    """
    get default values from sot

    Args:
        repo:
        filename:
        update:

    Returns:

    """

    defaults_str = helper.get_file(config["sot"]["api_endpoint"],
                                   repo,
                                   filename,
                                   update)

    if defaults_str is None:
        print("%s %s does not exists or could not be read" % (repo, filename))
        return None

    # convert defaults to dict
    try:
        data = yaml.safe_load(defaults_str)
    except Exception as exc:
        print("got exception: %s" % exc)
        return None

    return data


def origin_git(config, update=False):
    """

    Args:
        config:
        update:

    Returns:

    """

    # we use a dict to store our results
    result = {}

    repo = config['files']['sites']['repo']
    prefix_filename = config['files']['prefixe']['filename']
    defaults_filename = config['files']['defaults']['filename']
    sites_filename = config['files']['sites']['filename']

    # get default values from repo
    prefixe = get_defaults(repo, prefix_filename,update)
    if prefixe is None:
        print("could not read default values from %s/%s" % (repo, prefix_filename))
        return None

    defaults = get_defaults(repo, defaults_filename,update)
    if defaults is None:
        print("could not read default values from %s/%s" % (repo, defaults_filename))
        return None

    sites = get_defaults(repo, sites_filename,update)
    if sites is None:
        print("could not read default values from %s/%s" % (repo, sites_filename))
        return None

    # now add sites first
    for site in sites['sites']:
        data = {'name': site['name'],
                'slug': site['slug'],
                'status': site['status']
                }
        # send request to add site to nautobot
        result['sites'] = helper.send_request('addsite',
                                              config["sot"]["api_endpoint"],
                                              data)

        # check if site already exists
        # if so we update only if user set update to True
        if result['sites']['success'] and update:
            update_data = {}
            update_list = ['asn',
                           'time_zone',
                           'description',
                           'physical_address',
                           'shipping_address',
                           'latitude',
                           'longitude',
                           'contact_name',
                           'contact_phone',
                           'contact_email',
                           'comments']
            for u in update_list:
                if u in site:
                    update_data[update] = site[u]

            result['sites'] = helper.send_request('updatesite',
                                                  config["sot"]["api_endpoint"],
                                                  {'slug': site['slug'], 'config': update_data})

    # add manufacturers
    for m in defaults['manufacturers']:
        data = {'name': m['name'],
                'slug': m['slug']}
        result['manufacturers'] = helper.send_request('addmanufacturer',
                                                      config["sot"]["api_endpoint"],
                                                      data)

        if not result['manufacturers']['success'] and args.update:
            update_data = {}
            update_list = ['slug',
                           'name',
                           'description']
            for update in update_list:
                if update in m:
                    update_data[update] = m[update]
            result['manufacturers']  = helper.send_request('updatemanufacturer',
                         config["sot"]["api_endpoint"],
                         {'slug': m['slug'], 'config': update_data})

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
        result['platforms'] = helper.send_request('addplatform',
                                                  config["sot"]["api_endpoint"],
                                                  data)

        if not result['platforms']['success'] and args.update:
            update_data = {}
            update_list = ['slug',
                           'name',
                           'manufacturer',
                           'description',
                           'napalm_driver',
                           'napalm_args']
            for update in update_list:
                if update in p:
                    update_data[update] = p[update]
            result['platforms'] = sot.send_request('updateplatform',
                                                   config["sot"]["api_endpoint"],
                                                   {'slug': p['slug'], 'config': update_data})

    # add device types
    for d in defaults['devicetype']:
        data = {'model': d['model'],
                'slug': d['slug'],
                'manufacturer': d['manufacturer']}
        result['devicetype'] = helper.send_request('adddevicetype',
                                                   config["sot"]["api_endpoint"],
                                                   data)

        if not result['devicetype']['success'] and args.update:
            update_data = {}
            update_list = ['slug',
                           'model',
                           'manufacturer']
            for update in update_list:
                if update in d:
                    update_data[update] = d[update]
            result['devicetype'] = helper.send_request('updatedevicetype',
                                                       config["sot"]["api_endpoint"],
                                                       {'slug': d['slug'],
                                                        'config': update_data})

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
    config = helper.read_config(config_file)

    if args.repo:
        config['files']['sites']['repo'] = args.repo
    if args.filename:
        config['files']['sites']['filename'] = args.filename

    if args.origin == 'git':
        origin_git(config, args.update)
