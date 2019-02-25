# Copyright 2008-2018 Univa Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import shlex
from typing import List

from tortuga.resourceAdapterConfiguration import settings


AZURE_SETTINGS_DICT = {
    'subscription_id': settings.StringSetting(
        required=True,
        description='Azure subscription ID; obtainable from azure CLI or '
                    'Management Portal'
    ),
    'client_id': settings.StringSetting(
        required=True,
        description='Azure client ID; obtainable from azure CLI or '
                    'Management Portal'
    ),
    'tenant_id': settings.StringSetting(
        required=True,
        description='Azure tenant ID; obtainable from azure CLI or '
                    'Management Portal'
    ),
    'secret': settings.StringSetting(
        required=True,
        description='Azure client secret; obtainable from azure CLI or '
                    'Management Portal',
        secret=True
    ),
    'security_group': settings.StringSetting(
        required=True,
        description='Azure security group to associate with created '
                    'virtual machines'

    ),
    'resource_group': settings.StringSetting(
        required=True,
        description='Azure resource group where Tortuga will create '
                    'virtual machines'
    ),
    'storage_account': settings.StringSetting(
        required=True,
        description='Azure storage account where virtual disks for '
                    'Tortuga-managed nodes will be created'
    ),
    'location': settings.StringSetting(
        required=True,
        description='Azure region in which to create virtual machines',
        default='East US'
    ),
    'size': settings.StringSetting(
        required=True,
        description='"Size" of virtual machines',
        default='Basic_A2'
    ),
    'default_login': settings.StringSetting(
        required=True,
        description='Default user login on compute nodes. A login is '
                    'created by default on Tortuga-managed compute nodes '
                    'for the specified user.',
        default='azureuser'
    ),
    'virtual_network_name': settings.StringSetting(
        required=True,
        description='Name of virtual network to associate with virtual '
                    'machines',
        requires=['subnet_name']
    ),
    'subnet_name': settings.StringSetting(
        required=True,
        description='Name of subnet to be used within configured virtual '
                    'network',
        list=True
    ),
    'image_urn': settings.StringSetting(
        description='URN of desired operating system VM image',
        mutually_exclusive=['image'],
        overrides=['image']
    ),
    'image': settings.StringSetting(
        description='Name of VM image',
        mutually_exclusive=['image_urn'],
        overrides=['image_urn']
    ),
    'cloud_init_script_template': settings.FileSetting(
        required=True,
        description='Use this setting to specify the filename/path of'
                    'the cloud-init script template. If the path is not'
                    'fully-qualified (does not start with a leading'
                    'forward slash), it is assumed the script path is '
                    '$TORTUGA_ROOT/config',
        base_path='/opt/tortuga/config/',
        mutually_exclusive=['user_data_script_template'],
        overrides=['user_data_script_template']
    ),
    'user_data_script_template': settings.FileSetting(
        required=True,
        description='File name of bootstrap script template to be used '
                    'on compute nodes. If the path is not '
                    'fully-qualified (ie. does not start with a leading '
                    'forward slash), it is assumed the script path is '
                    '$TORTUGA_ROOT/config',
        base_path='/opt/tortuga/config/',
        mutually_exclusive=['cloud_init_script_template'],
        overrides=['cloud_init_script_template']
    ),
    'allocate_public_ip': settings.BooleanSetting(
        description='When disabled (value "false"), VMs created by '
                    'Tortuga will not have a public IP address.',
        default='True'
    ),
    'storage_account_type': settings.StringSetting(
        description='Use specified storage account type when using an VM '
                    'image.',
        default='Standard_LRS',
        values=['Standard_LRS', 'Premium_LRS']
    ),
    'tags': settings.StringSetting(
        description='Space-separated "key=value" pairs'
    ),
    'override_dns_domain': settings.BooleanSetting(
        display_name='Override DNS domain',
        description='Enable overriding of instances\' DNS domain',
        default='False',
    ),
    'dns_domain': settings.StringSetting(
        requires=['override_dns_domain']
    ),
    'dns_search': settings.StringSetting(
        description='Set search list for compute node host name lookup. '
                    'Default is the private DNS domain suffix if '
                    '"override_dns_domain" is enabled, otherwise '
                    'DNS domain suffix of Tortuga installer.'
    ),
    'dns_nameservers': settings.StringSetting(
        description='Space-separated list of IP addresses to be set in '
                    '/etc/resolv.conf. The default is the Tortuga DNS '
                    'server IP.',
        list=True,
        list_separator=' ',
    ),
    'ssh_key_value': settings.StringSetting(
        description='Specifies the SSH public key or public key file '
                    'path. If the value of this setting starts with a '
                    'forward slash (/), it is assumed to be a file path. '
                    'The SSH public key will be read from this file.'
    ),
    'vcpus': settings.IntegerSetting(
        description='Default behaviour is to use the virtual CPUs count '
                    'obtained from Azure. If vcpus is defined, it '
                    'overrides the default value.'
    ),
    'use_managed_disks': settings.BooleanSetting(
        default='True',
        advanced=True
    ),
    'ssd': settings.BooleanSetting(
        default='False',
        advanced=True
    ),
    'launch_timeout': settings.IntegerSetting(
        default='300',
        advanced=True
    )
}


def parse_tags(user_defined_tags):
    """Parse tags provided in resource adapter configuration"""

    tags = {}

    # Support tag names/values containing spaces and tags without a
    # value.
    for tagdef in shlex.split(user_defined_tags):
        key, value = tagdef.rsplit('=', 1) \
            if '=' in tagdef else (tagdef, '')

        tags[key] = value

    return tags


def _get_encoded_list(items: List[str]) -> str:
    """Return Python list encoded in a string"""
    return '[' + ', '.join(['\'%s\'' % (item) for item in items]) + ']' \
        if items else '[]'
