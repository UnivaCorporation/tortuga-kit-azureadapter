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
        display_name='Tags',
        description='A comma-separated list of tags in the form of '
                    'key=value',
        key_validation_regex='[^<>%&\\?/]{0,512}',
        value_validation_regex='.{0,256}',
        **GROUP_INSTANCES
    ),
    'security_group': settings.StringSetting(
        display_name='Security Group',
        description='Azure security group to associate with created '
                    'virtual machines',
        required=True,
        **GROUP_INSTANCES
    ),
    'resource_group': settings.StringSetting(
        display_name='Resource Group',
        required=True,
        description='Azure resource group where Tortuga will create '
                    'virtual machines',
        **GROUP_INSTANCES
    ),
    'storage_account': settings.StringSetting(
        display_name='Storage Account',
        required=True,
        description='Azure storage account where virtual disks for '
                    'Tortuga-managed nodes will be created',
        **GROUP_INSTANCES
    ),
    'location': settings.StringSetting(
        display_name='Location',
        description='Azure region in which to create virtual machines',
        required=True,
        default='East US',
        **GROUP_INSTANCES
    ),
    'size': settings.StringSetting(
        display_name='Size',
        description='"Size" of virtual machines',
        required=True,
        default='Basic_A2',
        **GROUP_INSTANCES
    ),
    'default_login': settings.StringSetting(
        display_name='Default Login',
        description='Default user login on compute nodes. A login is '
                    'created by default on Tortuga-managed compute nodes '
                    'for the specified user.',
        required=True,
        default='azureuser',
        **GROUP_INSTANCES
    ),
    'image_urn': settings.StringSetting(
        display_name='Image URN',
        description='URN of desired operating system VM image',
        mutually_exclusive=['image'],
        overrides=['image'],
        **GROUP_INSTANCES
    ),
    'image': settings.StringSetting(
        display_name='Image',
        description='Name of VM image',
        mutually_exclusive=['image_urn'],
        overrides=['image_urn'],
        **GROUP_INSTANCES
    ),
    'cloud_init_script_template': settings.FileSetting(
        display_name='Cloud Init Script Template',
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
        display_name='User Data Script Template',
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
        display_name='Storage Account Type',
        description='Use specified storage account type when using an VM '
                    'image.',
        default='Standard_LRS',
        values=['Standard_LRS', 'Premium_LRS'],
        **GROUP_INSTANCES
    ),
    'vcpus': settings.IntegerSetting(
        display_name='VCPUs',
        description='Default behaviour is to use the virtual CPUs count '
                    'obtained from Azure. If vcpus is defined, it '
                    'overrides the default value.',
        **GROUP_INSTANCES
    ),
    'use_managed_disks': settings.BooleanSetting(
        display_name='Use Managed Disks',
        default='True',
        advanced=True,
        **GROUP_INSTANCES
    ),
    'ssd': settings.BooleanSetting(
        display_name='SSD',
        default='False',
        advanced=True,
        **GROUP_INSTANCES
    ),
    'ssh_key_value': settings.StringSetting(
        display_name='SSH Key Value',
        description='Specifies the SSH public key or public key file '
                    'path. If the value of this setting starts with a '
                    'forward slash (/), it is assumed to be a file path. '
                    'The SSH public key will be read from this file.',
        **GROUP_INSTANCES
    ),
    'randomize_hostname': settings.BooleanSetting(
        display_name='Randomize Hostname',
        description='Append random string to generated host names'
                    'to prevent name collisions in highly dynamic '
                    'environments',
        default='True',
        **GROUP_INSTANCES
    ),

    #
    # Authentication
    #
    'subscription_id': settings.StringSetting(
        display_name='Subscription ID',
        description='Azure subscription ID; obtainable from azure CLI or '
                    'Management Portal',
        required=True,
        **GROUP_AUTHENTICATION
    ),
    'client_id': settings.StringSetting(
        display_name='Client ID',
        description='Azure client ID; obtainable from azure CLI or '
                    'Management Portal',
        required=True,
        mutually_exclusive=['credential_vault_path'],
        **GROUP_AUTHENTICATION
    ),
    'tenant_id': settings.StringSetting(
        display_name='Tenant ID',
        description='Azure tenant ID; obtainable from azure CLI or '
                    'Management Portal',
        required=True,
        **GROUP_AUTHENTICATION
    ),
    'secret': settings.StringSetting(
        display_name='Secret',
        description='Azure client secret; obtainable from azure CLI or '
                    'Management Portal',
        required=True,
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
        display_name='Override DNS Domain',
        description='Enable overriding of instances\' DNS domain',
        default='False',
        **GROUP_DNS
    ),
    'dns_domain': settings.StringSetting(
        display_name='DNS Domain',
        requires=['override_dns_domain'],
        **GROUP_DNS
    ),
    'dns_nameservers': settings.StringSetting(
        display_name='DNS Nameservers',
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
        display_name='Virtual Network Name',
        description='Name of virtual network to associate with virtual '
                    'machines',
        required=True,
        requires=['subnet_name'],
        **GROUP_NETWORKING
    ),
    'subnet_name': settings.StringSetting(
        display_name='Subnet Name',
        description='Name of subnet to be used within configured virtual '
                    'network',
        required=True,
        list=True,
        **GROUP_NETWORKING
    ),
    'allocate_public_ip': settings.BooleanSetting(
        display_name='Allocate Public IP',
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
        display_name='Launch Timeout',
        default='300',
        advanced=True
    ),
}
