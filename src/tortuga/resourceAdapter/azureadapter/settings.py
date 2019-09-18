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

from tortuga.resourceAdapterConfiguration import settings


AZURE_ASYNC_OP_TIMEOUT = 900

GROUP_INSTANCES = {
    'group': 'Instances',
    'group_order': 0
}
GROUP_AUTHENTICATION = {
    'group': 'Authentication',
    'group_order': 1
}
GROUP_DNS = {
    'group': 'DNS',
    'group_order': 2
}
GROUP_NETWORKING = {
    'group': 'Networking',
    'group_order': 3
}
GROUP_COST = {
    'group': 'Cost Sync',
    'group_order': 9
}

SETTINGS = {
    #
    # Instances
    #
    'tags': settings.TagListSetting(
        key_validation_regex='[^<>%&\\?/]{0,512}',
        value_validation_regex='.{0,256}',
        display_name='Tags',
        description='A comma-separated list of tags in the form of '
                    'key=value',
        **GROUP_INSTANCES
    ),
    'security_group': settings.StringSetting(
        required=True,
        description='Azure security group to associate with created '
                    'virtual machines',
        **GROUP_INSTANCES
    ),
    'resource_group': settings.StringSetting(
        required=True,
        description='Azure resource group where Tortuga will create '
                    'virtual machines',
        **GROUP_INSTANCES
    ),
    'storage_account': settings.StringSetting(
        required=True,
        description='Azure storage account where virtual disks for '
                    'Tortuga-managed nodes will be created',
        **GROUP_INSTANCES
    ),
    'location': settings.StringSetting(
        required=True,
        description='Azure region in which to create virtual machines',
        default='East US',
        **GROUP_INSTANCES
    ),
    'size': settings.StringSetting(
        required=True,
        description='"Size" of virtual machines',
        default='Basic_A2',
        **GROUP_INSTANCES
    ),
    'default_login': settings.StringSetting(
        required=True,
        description='Default user login on compute nodes. A login is '
                    'created by default on Tortuga-managed compute nodes '
                    'for the specified user.',
        default='azureuser',
        **GROUP_INSTANCES
    ),
    'image_urn': settings.StringSetting(
        description='URN of desired operating system VM image',
        mutually_exclusive=['image'],
        overrides=['image'],
        **GROUP_INSTANCES
    ),
    'image': settings.StringSetting(
        description='Name of VM image',
        mutually_exclusive=['image_urn'],
        overrides=['image_urn'],
        **GROUP_INSTANCES
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
        overrides=['user_data_script_template'],
        **GROUP_INSTANCES
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
        overrides=['cloud_init_script_template'],
        **GROUP_INSTANCES
    ),
    'storage_account_type': settings.StringSetting(
        description='Use specified storage account type when using an VM '
                    'image.',
        default='Standard_LRS',
        values=['Standard_LRS', 'Premium_LRS'],
        **GROUP_INSTANCES
    ),
    'vcpus': settings.IntegerSetting(
        description='Default behaviour is to use the virtual CPUs count '
                    'obtained from Azure. If vcpus is defined, it '
                    'overrides the default value.',
        **GROUP_INSTANCES
    ),
    'use_managed_disks': settings.BooleanSetting(
        default='True',
        advanced=True,
        **GROUP_INSTANCES
    ),
    'ssd': settings.BooleanSetting(
        default='False',
        advanced=True,
        **GROUP_INSTANCES
    ),
    'ssh_key_value': settings.StringSetting(
        description='Specifies the SSH public key or public key file '
                    'path. If the value of this setting starts with a '
                    'forward slash (/), it is assumed to be a file path. '
                    'The SSH public key will be read from this file.',
        **GROUP_INSTANCES
    ),

    #
    # Authentication
    #
    'subscription_id': settings.StringSetting(
        required=True,
        description='Azure subscription ID; obtainable from azure CLI or '
                    'Management Portal',
        **GROUP_AUTHENTICATION
    ),
    'client_id': settings.StringSetting(
        required=True,
        description='Azure client ID; obtainable from azure CLI or '
                    'Management Portal',
        mutually_exclusive=['credential_vault_path'],
        **GROUP_AUTHENTICATION
    ),
    'tenant_id': settings.StringSetting(
        required=True,
        description='Azure tenant ID; obtainable from azure CLI or '
                    'Management Portal',
        **GROUP_AUTHENTICATION
    ),
    'secret': settings.StringSetting(
        required=True,
        description='Azure client secret; obtainable from azure CLI or '
                    'Management Portal',
        secret=True,
        mutually_exclusive=['credential_vault_path'],
        **GROUP_AUTHENTICATION
    ),
    'credential_vault_path' : settings.StringSetting(
        display_name='Credential Vault Path',
        description='Path to Azure client credentials stored in Vault.',
        mutually_exclusive=['secret','client_id'],
        **GROUP_AUTHENTICATION
    ),

    #
    # DNS
    #
    'override_dns_domain': settings.BooleanSetting(
        display_name='Override DNS domain',
        description='Enable overriding of instances\' DNS domain',
        default='False',
        **GROUP_DNS
    ),
    'dns_domain': settings.StringSetting(
        requires=['override_dns_domain'],
        **GROUP_DNS
    ),
    'dns_nameservers': settings.StringSetting(
        description='Space-separated list of IP addresses to be set in '
                    '/etc/resolv.conf. The default is the Tortuga DNS '
                    'server IP.',
        list=True,
        list_separator=' ',
        **GROUP_DNS
    ),

    #
    # Networking
    #
    'virtual_network_name': settings.StringSetting(
        required=True,
        description='Name of virtual network to associate with virtual '
                    'machines',
        requires=['subnet_name'],
        **GROUP_NETWORKING
    ),
    'subnet_name': settings.StringSetting(
        required=True,
        description='Name of subnet to be used within configured virtual '
                    'network',
        list=True,
        **GROUP_NETWORKING
    ),
    'allocate_public_ip': settings.BooleanSetting(
        description='When disabled (value "false"), VMs created by '
                    'Tortuga will not have a public IP address.',
        default='True',
        **GROUP_NETWORKING
    ),

    #
    # Settings for Navops Launch 2.0
    #
    'cost_sync_enabled': settings.BooleanSetting(
        display_name='Cost Synchronization Enabled',
        description='Enable Azure cost synchronization',
        requires=['cost_storage_account', 'cost_storage_account_key',
                  'cost_storage_container_name', 'cost_directory_name',
                  'cost_report_name'],
        **GROUP_COST
    ),
    'cost_storage_account': settings.StringSetting(
        display_name='Storage Account',
        requires=['cost_sync_enabled'],
        description='The name of the Azure storage account where cost '
                    'reports are saved',
        **GROUP_COST
    ),
    'cost_storage_account_key': settings.StringSetting(
        display_name='Storage Account Key',
        secret=True,
        requires=['cost_sync_enabled'],
        description='The access key for the storage account where cost '
                    'reports are saved',
        **GROUP_COST
    ),
    'cost_storage_container_name': settings.StringSetting(
        display_name='Storage Container Name',
        requires=['cost_sync_enabled'],
        description='The name of the Azure storage container in the storage '
                    'account where cost reports are saved',
        **GROUP_COST
    ),
    'cost_directory_name': settings.StringSetting(
        display_name='Directory Name',
        requires=['cost_sync_enabled'],
        description='The name of the directory in the storage container '
                    'in which to scan for cost reports',
        **GROUP_COST
    ),
    'cost_report_name': settings.StringSetting(
        display_name='Report Name',
        requires=['cost_sync_enabled'],
        description='The name of the cost report',
        **GROUP_COST
    ),

    #
    # Unspecified
    #
    'launch_timeout': settings.IntegerSetting(
        default='300',
        advanced=True
    ),
}
