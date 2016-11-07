#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2016, Nicklaus McClendon <nicklaus@kulinacs.com>
# (c) 2016, Yanis Guenane <yanis+ansible@guenane.org>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

from ansible.module_utils.basic import *

import os

DOCUMENTATION = '''
---
module: openssh_privatekey
author: "Nicklaus McClendon (@kulinacs)"
version_added: "2.3"
short_description: Generate OpenSSH private keys
requirements: [ python-cryptography ]
description:
    - Generate and deploy OpenSSH private keys
options:
    state:
        required: false
        default: "present"
        choices: [ present, absent ]
        description:
            - Whether the private key should exist or not, taking action if the
              state is different from what is stated.
    size:
        required: false
        default: 2048
        description:
            - Size (in bits) of the OpenSSH key to generate
    type:
        required: false
        default: "RSA"
        options: [ RSA, DSA, ECDSA ]
        description:
            - The algorithm used to generate the OpenSSH key
    force:
        required: false
        default: False
        choices: [ True, False ]
        description:
            - Should the key be regenerated even it it already exists
    path:
        required: true
        description:
            - Name of the file in which the generated OpenSSH private key will
              be written. It will have 0600 mode.
'''

EXAMPLES = '''
# Generate an OpenSSH private key with the default values (2048 bits, RSA)
- openssh_privatekey: path=/etc/ssh/ssh_host_rsa_key

# Generate an OpenSSH private key with a different size (4096 bits)
- openssh_privatekey: path=/etc/ssh/ssh_host_rsa_key

# Force regenerate an OpenSSH private key if it already exists
- openssh_privatekey: path=/etc/ssh/ssh_host_rsa_key force=True

# Generate an OpenSSH private key with a different algorithm (ECDSA)
- openssl_privatekey: path=/etc/ssh/ssh_host_ecdsa_key type=ECDSA
'''

RETURN = '''
size:
    description: Size (in bits) of the OpenSSH private key
    returned:
        - changed
        - success
    type: integer
    sample: 4096
type:
    description: Algorithm used to generate the OpenSSH private key
    returned:
        - changed
        - success
    type: string
    sample: RSA
filename:
    description: Path to the generated OpenSSH private key file
    returned:
        - changed
        - success
    type: string
    sample: /etc/ssh/ssh_host_rsa_key
'''
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives import asymmetric
    from cryptography.hazmat.backends import default_backend
    HAVE_CRYPTOGRAPHY = True
except:
    HAVE_CRYPTOGRAPHY = False


class OpenSSHPrivateKeyError(Exception):
    pass


class OpenSSHPrivateKey(object):

    def __init__(self, module):
        self.size = module.params['size']
        self.state = module.params['state']
        self.name = os.path.basename(module.params['path'])
        self.type = module.params['type']
        self.force = module.params['force']
        self.path = module.params['path']
        self.mode = module.params['mode']
        self.changed = True
        self.check_mode = module.check_mode

    def generate(self, module):
        """Generate a private key."""

        if not os.path.exists(self.path) or self.force:

            if self.type == 'RSA':
                key = self.generate_rsa(self.size)
            elif self.type == 'ECDSA':
                key = self.generate_ecdsa(self.size)
            else:
                key = self.generate_dsa()

            keyfile = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption())

            try:
                privatekey_file = os.open(self.path,
                                          os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                                          self.mode)

                os.write(privatekey_file, keyfile)
                os.close(privatekey_file)
            except IOError:
                self.remove()
                raise OpenSSHPrivateKeyError(get_exception())
        else:
            self.changed = False

        file_args = module.load_file_common_arguments(module.params)
        if module.set_fs_attributes_if_different(file_args, False):
            self.changed = True

    def generate_rsa(self, size):
        if size > 1023:
            try: 
                key = asymmetric.rsa.generate_private_key(
                    backend=default_backend(),
                    public_exponent=65537,
                    key_size=size
                )
                return key
            except:
                raise OpenSSHPrivateKeyError(get_exception())
        else:
            raise OpenSSHPrivateKeyError("Invalid RSA Keysize")

    def generate_dsa(self):
        try:
            key = asymmetric.dsa.generate_private_key(
                backend=default_backend(),
                key_size=1024
                )
            return key
        except:
            raise OpenSSHPrivateKeyError(get_exception())

    def generate_ecdsa(self, size):
        if size == 256:
            try:
                key = asymmetric.ec.generate_private_key(
                    backend=default_backend(),
                    curve=asymmetric.ec.SECP256R1
                )
                return key
            except:
                raise OpenSSHPrivateKeyError(get_exception())
        elif size == 384:
            try:
                key = asymmetric.ec.generate_private_key(
                    backend=default_backend(),
                    curve=asymmetric.ec.SECP384R1
                )
                return key
            except:
                raise OpenSSHPrivateKeyError(get_exception())
        elif size == 521:
            try:
                key = asymmetric.ec.generate_private_key(
                    backend=default_backend(),
                    curve=asymmetric.ec.SECP521R1
                )
                return key
            except:
                raise OpenSSHPrivateKeyError(get_exception())
        else:
            raise OpenSSHPrivateKeyError("Invalid ECDSA Keysize")

    def remove(self):
        """Remove the private key from the filesystem."""

        try:
            os.remove(self.path)
        except OSError:
            e = get_exception()
            if e.errno != errno.ENOENT:
                raise PrivateKeyError(e)
            else:
                self.changed = False

    def dump(self):
        """Serialize the object into a dictionnary."""

        result = {
            'size': self.size,
            'type': self.type,
            'filename': self.path,
            'changed': self.changed,
        }

        return result

def main():
    module = AnsibleModule(
        argument_spec = dict(
            state=dict(default='present', choices=['present', 'absent'], type='str'),
            size=dict(default=2048, type='int'),
            type=dict(default='RSA', choices=['RSA', 'DSA', 'ECDSA'], type='str'),
            force=dict(default=False, type='bool'),
            path=dict(required=True, type='path'),
        ),
        supports_check_mode = True,
        add_file_common_args = True,
    )

    if not HAVE_CRYPTOGRAPHY:
        module.fail_json(msg='the python cryptography module is required')

    path = module.params['path']
    base_dir = os.path.dirname(module.params['path'])

    if not os.path.isdir(base_dir):
        module.fail_json(name=base_dir, msg='The directory %s does not exist or the file is not a directory' % base_dir)

    if not module.params['mode']:
        module.params['mode'] = int('0600', 8)

    private_key = OpenSSHPrivateKey(module)
    if private_key.state == 'present':

        if module.check_mode:
            result = private_key.dump()
            result['changed'] = module.params['force'] or not os.path.exists(path)
            module.exit_json(**result)

        try:
            private_key.generate(module)
        except OpenSSHPrivateKeyError:
            e = get_exception()
            module.fail_json(msg=str(e))
    else:

        if module.check_mode:
            result = private_key.dump()
            result['changed'] = os.path.exists(path)
            module.exit_json(**result)

        try:
            private_key.remove()
        except OpenSSHPrivateKeyError:
            e = get_exception()
            module.fail_json(msg=str(e))

    result = private_key.dump()

    module.exit_json(**result)


if __name__ == '__main__':
    main()
