import keyring
import argparse
import getpass
import base64
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# please set secure salt BEFORE you use this script eg. os.urandom(16)
salt = b"mysecretsalt"

# this scripts either:
#   - sets the password for a specified user using the keyring mechanism
#   - encrypts the password using an encryptionkey and the salt configured above
#   - decrypts entered password using the encryptionkey and the salt configured above

yes_choices = ['yes', 'y']
no_choices = ['no', 'n']

parser = argparse.ArgumentParser()
parser.add_argument('--username', type=str, required=False)
parser.add_argument('--password', type=str, required=False)
parser.add_argument('--show', type=bool, default=False, required=False)
parser.add_argument('--set', type=bool, default=False, required=False)
parser.add_argument('--encrypt', type=bool, default=False, required=False)
parser.add_argument('--decrypt', type=bool, default=False, required=False)
parser.add_argument('--encryptionkey', type=str, required=False)
args = parser.parse_args()

# we need a username to encrypt or show the password
if args.show or args.encrypt or args.set:
    if args.username is None:
        username = input("Username (%s): " % getpass.getuser())
    else:
        username = args.username

if args.show:
    password = keyring.get_password("nal", username)
    print("password of %s is %s" % (username, password))
    sys.exit(0)

if args.set:
    if args.password is None:
        password = getpass.getpass(prompt="Enter password for %s: " % username)
    else:
        password = args.password

    keyring.set_password("nal", username, password)
    sys.exit(0)

if args.encrypt:
    if args.password is None:
        # use the keyring password
        password = keyring.get_password("nal", username)
        if password is not None:
            user_input = input("Use keyring? (yes/no)")
            if user_input.lower() in yes_choices:
                print("using keyring")
            else:
                password = getpass.getpass(prompt="Enter password for %s: " % username)
        else:
            password = getpass.getpass(prompt="Enter password for %s: " % username)
    else:
        password = args.password

    if args.encryptionkey is None:
        encrypt_pwd = getpass.getpass(prompt="Enter encryptionkey for %s: " % username)
    else:
        encrypt_pwd = args.encryptionkey

    password_bytes = str.encode(password)
    encrypt_pwd_bytes = str.encode(encrypt_pwd)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(encrypt_pwd_bytes))
    f = Fernet(key)
    token = f.encrypt(password_bytes)
    print("token: %s" % base64.b64encode(token))


if args.decrypt:
    if args.encryptionkey is None:
        encrypt_key = getpass.getpass(prompt="Enter encryptionkey: ")
    else:
        encrypt_key = args.encryptionkey
    encrypt_key_bytes = str.encode(encrypt_key)

    # get token as base64 and convert it to byte
    token_ascii = input("Enter token: ")
    token_bytes = base64.b64decode(token_ascii)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(encrypt_key_bytes))

    f = Fernet(key)
    try:
        print ("decrypted: %s" % f.decrypt(token_bytes))
    except Exception as e:
        print("Wrong encryption key or salt %s" % e)

