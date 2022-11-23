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

    # get default values of prefixes
    repo = args.repo or config['files']['sites']['repo']
    filename = args.filename or config['files']['sites']['filename']
    sites_str = get_file(config["sot"]["api_endpoint"],
                         repo,
                         filename)
    if sites_str is None:
        print ("%s %s does not exists or could not be read" % (repo, filename))
        sys.exit(-1)

    sites = None
    try:
        sites_yaml = yaml.safe_load(sites_str)
        if sites_yaml is not None and 'sites' in sites_yaml:
           sites = sites_yaml['sites']
    except Exception as exc:
        print ("got exception: %s" % exc)

    # we use a dict to store our results
    result = {}
    result['logs'] = []
    result['success'] = []

    for site in sites:
        data = {'name': site['name'],
                'slug': site['slug'],
                'status': site['status']
        }
        send_request('addsite',
                     config["sot"]["api_endpoint"],
                     data,
                     result,
                     'site',
                     'site added')

        # check if site already exists
        # if so we update only if user set update to True
        if not result['success'][0] and not args.update:
            print(json.dumps(result, indent=4))
            sys.exit(0)

        update_data = {}
        update_list = ['asn','time_zone','description','physical_address',
                       'shipping_address','latitude','longitude','contact_name',
                       'contact_phone','contact_email','comments']
        for update in update_list:
            if update in site:
                update_data[update] = site[update]

        send_request('updatesite',
                     config["sot"]["api_endpoint"],
                     {'slug': site['slug'], 'config': update_data},
                     result,
                     'site',
                     '%s updated' % site['slug'])

        print (json.dumps(result,indent=4))


if __name__ == "__main__":
    add_defaults_to_sot()