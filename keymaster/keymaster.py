import argparse
import base64
import json
import hashlib
import random
import os
import getpass

from Crypto.Cipher import AES
from Crypto import Random

ROOT_FILENAME = 'keymaster_store'
EXT_PASSWORD = 'keymaster_password'

def generate_salt():
    ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    chars=''
    for i in range(32):
        chars += random.choice(ALPHABET)
    return chars
        
class KeymasterConfig(object):
    
    def __init__(self):
        self.salt = None
        self.challenge = None
        self.encoded_challenge = None 
    
    def to_dict(self):
        return {
            'salt': self.salt,
            'challenge': self.challenge,
            'encoded_challenge': self.encoded_challenge,
        }
    
    def from_dict(self, dict_param):
        self.salt = dict_param['salt']
        self.challenge = dict_param['challenge']
        self.encoded_challenge = dict_param['encoded_challenge']
    
    def gen(self):
        self.salt = generate_salt()
        self.challenge = generate_salt()


def keymaster_full_filepath(path):
    return os.path.join(path, ROOT_FILENAME)

def save_keymaster_config(keymaster_config, path):
    content = keymaster_config.to_dict()
    json_output = json.dumps(content, indent=2)
    f = open(keymaster_full_filepath(path), 'w')
    f.write(json_output)
    f.flush()
    f.close()
    print json_output

def load_keymaster_config(path):
    json_input = open(keymaster_full_filepath(path), 'r').read()
    result_dict = json.loads(json_input)
    result = KeymasterConfig()
    result.from_dict(result_dict)
    return result

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]



class Keymaster(object):
    def __init__(self, path, password):
        self.path = path
        self.keymaster_config = load_keymaster_config(self.path)
        self.password = password 

    def get_key(self):
        result = hashlib.md5( self.keymaster_config.salt + self.password ).digest()
        return result

    def verify_password(self):
        challenge = self.decrypt_string(self.keymaster_config.encoded_challenge)
        if challenge == self.keymaster_config.challenge:
            print "password verified"
        else:
            raise RuntimeError('Invalid password')

    def encrypt_string(self, plaintext):
        plaintext = pad(plaintext)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new( self.get_key(), AES.MODE_CBC, iv)
        return base64.b64encode( iv + cipher.encrypt( plaintext ) )

    def decrypt_string( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.get_key(), AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))

    def get_password_full_filepath(self, path, name):
        filename = '{}.{}'.format(name, EXT_PASSWORD)
        full_filepath = os.path.join(path, filename)
        return full_filepath

    def store_password(self, path, name, url, account, account_password):
        full_filepath = self.get_password_full_filepath(path, name)

        raw_content = json.dumps(
            {
                'url':url,
                'account':account,
                'password':account_password
            }
        )
        content = self.encrypt_string(raw_content)
        open(full_filepath, 'w').write(content)

    def load_password(self, path, name):
        full_filepath = self.get_password_full_filepath(path, name)
        encrypted_content = open(full_filepath, 'r').read()
        decrypted_json = self.decrypt_string(encrypted_content)
        content = json.loads(decrypted_json)#['password']
        return content

def find_keymaster_root(start_dir, max_travel=20):
    for _ in range(max_travel):
        print "start_dir: ", start_dir
        if os.path.isfile(keymaster_full_filepath(start_dir)):
            return start_dir
        start_dir = os.path.dirname(start_dir)
    raise RuntimeError('Can not find keymaster root')

def build_keymaster():
    cwd = os.getcwd()
    store_root = find_keymaster_root(cwd)
    password = getpass.getpass('password')
    return Keymaster(store_root, password)

def init(parser):
    args = parser.parse_args()
    cwd = os.getcwd()
    if os.path.isfile(keymaster_full_filepath(cwd)):
        raise RuntimeError('This is already keymaster root')
    cfg = KeymasterConfig()
    cfg.gen()
    save_keymaster_config(cfg, cwd)
    password = getpass.getpass('password')
    re_typed_password = getpass.getpass('re-type password:')
    if password != re_typed_password:
        raise RuntimeError('Passwords do not match')
    #km = build_keymaster()
    km = Keymaster(cwd, password)
    cfg.encoded_challenge = km.encrypt_string(cfg.challenge)
    save_keymaster_config(cfg, cwd)
    km = Keymaster(cwd, password)
    km.verify_password()

def add(parser):
    cwd = os.getcwd()
    #parser.add_argument('operation', type=str, choices=['init', 'add', 'remove', 'edit'])
    parser.add_argument('secret_type', type=str, choices=['password'])
    parser.add_argument('name', type=str)

    args = parser.parse_args()

    km = build_keymaster()
    km.verify_password()

    full_filepath = km.get_password_full_filepath(cwd, args.name)
    if os.path.isfile(full_filepath):
        raise RuntimeError("File already exists {}".format(full_filepath))
    
    url = raw_input("url: ")
    account = raw_input("account: ")
    
    password = getpass.getpass('password: ')
    re_typed_password = getpass.getpass('re-type password: ')
    if password != re_typed_password:
        raise RuntimeError('Passwords do not match')

    km.store_password(cwd, args.name, url, account, password)
    pass

def edit(parser):
    args = parser.parse_args()
    km = build_keymaster()
    km.verify_password()
    raise RuntimeError('implement me')

def view(parser):
    cwd = os.getcwd()
    parser.add_argument('secret_type', type=str, choices=['password'])
    parser.add_argument('name', type=str)
    
    args = parser.parse_args()
    km = build_keymaster()
    km.verify_password()
    
    content = km.load_password(cwd, args.name)
    print json.dumps(content, indent=2)

def remove(parser):
    args = parser.parse_args()
    km = build_keymaster()
    km.verify_password()
    raise RuntimeError('implement me')

def main():
    
    parser2 = argparse.ArgumentParser(description='Keymaster password manager')
    parser2.add_argument('operation', type=str, choices=['init', 'add', 'remove', 'edit', 'view'])
    parser2.add_argument('vars',nargs='*')
    args = parser2.parse_args()
    
    parser = argparse.ArgumentParser(description='Keymaster password manager')
    parser.add_argument('operation', type=str, choices=['init', 'add', 'remove', 'edit', 'view'])

    operations = {
        'init':init,
        'add':add,
        'edit':edit,
        'remove':remove,
        'view':view
    }

    operations[args.operation](parser)

if __name__ == '__main__':
    main()

