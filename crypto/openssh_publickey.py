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
module: openssh_publickey
author: "Nicklaus McClendon (@kulinacs)"
version_added: "2.3"
short_description: Generate OpenSSH public keys
requirements: [ python-cryptography ]
description:
    - Generate and deploy OpenSSH public keys from private keys
options:
    state:
        required: false
        default: "present"
        choices: [ present, absent ]
        description:
            - Whether the public key should exist or not, taking action if the
              state is different from what is stated.
    force:
        required: false
        default: False
        choices: [ True, False ]
        description:
            - Should the key be regenerated even it it already exists
    path:
        required: true
        description:
            - Name of the file in which the generated OpenSSH public key will
              be written. It will have 0644 mode.
    privatekey_path:
        required: true
        description:
            - Name of the private key to generate the public key from

'''

EXAMPLES = '''
# Generate an OpenSSH public key
- openssh_privatekey: path=/etc/ssh/ssh_host_rsa_key.pub privatekey_path=/etc/ssh/ssh_host_rsa_key

# Force regenerate an OpenSSH public key if it already exists
- openssh_privatekey: path=/etc/ssh/ssh_host_rsa_key.pub privatekey_path=/etc/ssh/ssh_host_rsa_key force=True

'''

RETURN = '''
privatekey:
    description: Path to the source OpenSSH private key file
    returned:
        - changed
        - success
    type: string
    sample: /etc/ssh/ssh_host_rsa_key
filename:
    description: Path to the generated OpenSSH public key file
    returned:
        - changed
        - success
    type: string
    sample: /etc/ssh/ssh_host_rsa_key.pub
'''
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives import asymmetric
    from cryptography.hazmat.backends import default_backend
    HAVE_CRYPTOGRAPHY = True
except:
    HAVE_CRYPTOGRAPHY = False


class OpenSSHPublicKeyError(Exception):
    pass


class OpenSSHPublicKey(object):
    def __init__(self, module):
        self.state = module.params['state']
        self.force = module.params['force']
        self.name = os.path.basename(module.params['path'])
        self.path = module.params['path']
        self.privatekey_path = module.params['privatekey_path']
        self.mode = module.params['mode']
        self.changed = True
        self.check_mode = module.check_mode


    def generate(self, module):
        """Generate the public key.."""

        if not os.path.exists(self.path) or self.force:
            try:
                privatekey_content = open(self.privatekey_path, 'r').read()
                privatekey = serialization.load_pem_private_key(
                    data=privatekey_content,
                    password=None,
                    backend=default_backend())
                publickey = privatekey.public_key().public_bytes(
                        serialization.Encoding.OpenSSH,
                        serialization.PublicFormat.OpenSSH
                )
                publickey_file = os.open(self.path,
                                          os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                                          self.mode)
                os.write(publickey_file, publickey)
                os.close(publickey_file)
            except (IOError, OSError):
                e = get_exception()
                raise OpenSSHPublicKeyError(e)
        else:
            self.changed = False

        file_args = module.load_file_common_arguments(module.params)
        if module.set_fs_attributes_if_different(file_args, False):
            self.changed = True

    def remove(self):
        """Remove the public key from the filesystem."""

        try:
            os.remove(self.path)
        except OSError:
            e = get_exception()
            if e.errno != errno.ENOENT:
                raise OpenSSHPublicKeyError(e)
            else:
                self.changed = False

    def dump(self):
        """Serialize the object into a dictionnary."""

        result = {
            'privatekey': self.privatekey_path,
            'filename': self.path,
            'changed': self.changed,
        }

        return result
        

def main():

    module = AnsibleModule(
        argument_spec = dict(
            state=dict(default='present', choices=['present', 'absent'], type='str'),
            force=dict(default=False, type='bool'),
            path=dict(required=True, type='path'),
            privatekey_path=dict(type='path'),
        ),
        supports_check_mode = True,
        add_file_common_args = True,
    )

    if not HAVE_CRYPTOGRAPHY:
        module.fail_json(msg='the python cryptography module is required')

    path = module.params['path']
    privatekey_path = module.params['privatekey_path']
    base_dir = os.path.dirname(module.params['path'])

    if not os.path.isdir(base_dir):
        module.fail_json(name=base_dir, msg='The directory %s does not exist or the file is not a directory' % base_dir)

    if not module.params['mode']:
        module.params['mode'] = int('0644', 8)
        
    public_key = OpenSSHPublicKey(module)
    if public_key.state == 'present':

        # This is only applicable when generating a new public key.
        # When removing one the privatekey_path should not be required.
        if not privatekey_path:
            module.fail_json(msg='When generating a new public key you must specify a private key')

        if not os.path.exists(privatekey_path):
            module.fail_json(name=privatekey_path, msg='The private key %s does not exist' % privatekey_path)

        if module.check_mode:
            result = public_key.dump()
            result['changed'] = module.params['force'] or not os.path.exists(path)
            module.exit_json(**result)

        try:
            public_key.generate(module)
        except OpenSSHPublicKeyError:
            e = get_exception()
            module.fail_json(msg=str(e))
    else:

        if module.check_mode:
            result = public_key.dump()
            result['changed'] = os.path.exists(path)
            module.exit_json(**result)

        try:
            public_key.remove()
        except OpenSSHPublicKeyError:
            e = get_exception()
            module.fail_json(msg=str(e))

    result = public_key.dump()

    module.exit_json(**result)


if __name__ == '__main__':
    main()
