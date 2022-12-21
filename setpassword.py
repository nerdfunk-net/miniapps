import keyring
import argparse
import getpass
import hashlib
import os


parser = argparse.ArgumentParser()
parser.add_argument('--username', type=str, required=False)
parser.add_argument('--password', type=str, required=False)
parser.add_argument('--show', type=bool, default=False, required=False)
parser.add_argument('--hash', type=bool, default=False, required=False)

args = parser.parse_args()

if args.username is None:
    username = input("Username (%s): " % getpass.getuser())
else:
    username = args.username

if args.show:
    password = keyring.get_password("nal", username)
    print("password of %s is %s" % (username, password))
else:
    if args.password is None:
        password = getpass.getpass(prompt="Enter password for %s: " % username)
    else:
        password = args.password

    if args.hash:
        plaintext = keyring.get_password("nal", username).encode()
        salt = os.urandom(32)
        digest = hashlib.pbkdf2_hmac('sha256',
                                     plaintext,
                                     salt,
                                     10000)
        hex_hash = digest.hex()
        print(hex_hash)
    else:
        keyring.set_password("nal", username, password)
