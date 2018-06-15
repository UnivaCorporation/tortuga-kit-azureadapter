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

import mock
import pytest

from tortuga.resourceAdapter.azureadapter.azureadapter \
    import AzureAdapter, ResourceAdapter
from tortuga.exceptions.configurationError import ConfigurationError


def myfunc(load_config_dict_mock, sectionName=None):
    if sectionName == 'testing':
        return {
            'cloud_init_script_template': '/etc/resolv.conf',
            'image_urn': 'value1:value2:value3:value4',
        }

    return {
        'subscription_id': '123',
        'client_id': '234',
        'secret': 'password',
        'tenant_id': '345',
        'resource_group': 'resource-group',
        'security_group': 'my-nsg',
        'default_login': 'myuser',
        'user_data_script_template': '/etc/hosts',
        'ssh_key_value': 'ssh-rsa ...',
        'image': 'myimage',
        'use_managed_disks': 'true',
    }


@mock.patch('tortuga.resourceAdapter.azureadapter.azureadapter.AzureAdapter.private_dns_zone', new_callable=mock.PropertyMock)
@mock.patch.object(AzureAdapter, '_loadConfigDict', new=myfunc)
def test_default_config(private_dns_zone_mock):
    private_dns_zone_mock.return_value = 'example.com'

    adapter = AzureAdapter()

    config = adapter.getResourceAdapterConfig()


@mock.patch('tortuga.resourceAdapter.azureadapter.azureadapter.AzureAdapter.private_dns_zone', new_callable=mock.PropertyMock)
@mock.patch.object(AzureAdapter, '_loadConfigDict', return_value={})
def test_invalid_empty_config(load_config_dict_mock, private_dns_zone_mock):
    private_dns_zone_mock.return_value = 'example.com'

    with pytest.raises(ConfigurationError):
        AzureAdapter().getResourceAdapterConfig()


@mock.patch('tortuga.resourceAdapter.azureadapter.azureadapter.AzureAdapter.private_dns_zone', new_callable=mock.PropertyMock)
@mock.patch.object(AzureAdapter, '_loadConfigDict', new=myfunc)
def test_basic(private_dns_zone_mock):
    private_dns_zone_mock.return_value = 'example.com'

    config = AzureAdapter().getResourceAdapterConfig(sectionName='testing')

    assert 'user_data_script_template' not in config

    assert 'cloud_init_script_template' in config

    assert 'image_urn' in config

    assert 'image' not in config
