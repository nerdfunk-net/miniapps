import yaml
import requests
import json
import os
import base64
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def read_config(filename):
    """
    read config from file
    Returns: json
    """
    with open(filename) as f:
        return yaml.safe_load(f.read())


def get_value_from_dict(dictionary, keys):
    if dictionary is None:
        return None

    nested_dict = dictionary

    for key in keys:
        try:
            nested_dict = nested_dict[key]
        except KeyError as e:
            return None
        except IndexError as e:
            return None

    return nested_dict


def send_request(url, api_endpoint, json_data):
    """
      send request to network abstraction layer
    Args:
        url:
        api_endpoint:
        json_data:

    Returns:
        result (success: true or false, error in case of false)
    """
    #
    # please note: check config.yaml and check if a // is not part of the URL!
    #
    url_request = "%s/onboarding/%s" % (api_endpoint, url)
    r = requests.post(url=url_request, json=json_data)

    if r.status_code != 200:
        return {'success': False, 'logs': 'got status code %i' % r.status_code}
    else:
        # we got a json. parse it and check if we have a success or not
        response = json.loads(r.content)
        if response["success"]:
            return {'success': True,
                    'id': response.get('id'),
                    'log': "%s" % response.get('log')}
        else:
            return {'success': False,
                    'error': "%s " % response.get('error')}


def get_file(api_endpoint, repo, filename, pull=False):
    """

    Args:
        api_endpoint:
        repo:
        filename:
        pull:

    Returns:
        content of file
    """
    r = requests.get(url="%s/get/%s/%s?update=%s" % (api_endpoint,
                                                     repo,
                                                     filename,
                                                     pull))
    if r.status_code != 200:
        logging.error('got status code %i' % r.status_code)
    else:
        # we got a json. parse it and check if we have a success or not
        response = json.loads(r.content)
        if response["success"]:
            content = response['content'].replace("\\n", "\n")
            return content
        else:
            logging.error("error getting file %s/%s; Error: %s" % (repo, filename, response['error']))

    return None


def decrypt_password(password):
    """

    decrypts base64 password that is stored in our yaml config

    Args:
        password:

    Returns: clear password

    """
    # prepare salt
    salt_ascii = os.getenv('SALT')
    salt_bytes = str.encode(salt_ascii)

    # prepare encryption key, we need it as bytes
    encryption_key_ascii = os.getenv('ENCRYPTIONKEY')
    encryption_key_bytes = str.encode(encryption_key_ascii)

    # get password as base64 and convert it to bytes
    password_bytes = base64.b64decode(password)

    # derive key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(encryption_key_bytes))

    f = Fernet(key)
    # decrypt and return
    try:
        return f.decrypt(password_bytes).decode("utf-8")
    except:
        return None


def get_profile(config, profilename='default'):
    """
        gets profile (username and password) from config
    Args:
        config:
        profilename:

    Returns: account as dict

    """

    result = {}
    clear_password = None

    username = get_value_from_dict(config, ['accounts',
                                            'devices',
                                            profilename,
                                            'username'])
    password = get_value_from_dict(config, ['accounts',
                                            'devices',
                                            profilename,
                                            'password'])

    if password is not None:
        clear_password = decrypt_password(password)

    if clear_password is None:
        return {'success': False, 'reason': 'wrong password'}
    else:
        return {'success': True, 'username': username, 'password': clear_password}
