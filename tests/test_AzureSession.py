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

import unittest
import configparser
import ssl

import testhelper

from tortuga.resourceAdapter.azureadapter import AzureSession
from tortuga.exceptions.configurationError import ConfigurationError


class TestAzureSession(unittest.TestCase):
    def test_init(self):
        session = AzureSession()

    def test_override_init(self):
        cfgfile = '/tmp/test-azure.cfg'

        testhelper.create_empty_cfg(cfgfile, 'azure')

        cfg = configparser.ConfigParser()
        cfg.read(cfgfile)

        cfg.set('resource-adapter',
                'subscription_id',
                '317d77e1-fa4a-4400-9f79-4c9e0d328461')

        cfg.set('resource-adapter',
                'service_certificate_path',
                '/root/work/test.pem')

        with open(cfgfile, 'w') as fp:
            cfg.write(fp)

        session = AzureSession(cfgfile=cfgfile)

        session.sms.list_os_images()

    def test_empty_cfg(self):
        cfgfile = '/tmp/azure-empty.cfg'

        testhelper.create_empty_cfg(cfgfile, 'azure')

        self.assertRaises(ConfigurationError, AzureSession, cfgfile=cfgfile)

        # session.sms.list_os_images()

    def test_invalid_cfg(self):
        cfgfile = '/tmp/test-azure.cfg'

        testhelper.create_empty_cfg(cfgfile, 'azure')

        cfg = configparser.ConfigParser()
        cfg.read(cfgfile)

        cfg.set('resource-adapter', 'subscription_id', 'blah')
        cfg.set('resource-adapter', 'service_certificate_path', 'blah')

        with open(cfgfile, 'w') as fp:
            cfg.write(fp)

        session = AzureSession(cfgfile=cfgfile)

        self.assertRaises(ssl.SSLError, session.sms.list_os_images)
