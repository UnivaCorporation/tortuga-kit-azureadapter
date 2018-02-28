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

import os
import unittest

from tortuga.exceptions.configurationError import ConfigurationError
from testhelper import init_cfg_obj, create_empty_cfg


class TestResourceAdapterConfigParser(unittest.TestCase):

    def test_init(self):
        """Check basic initialization"""

        cfg = init_cfg_obj('blah.cfg', 'ralph')

        self.assertTrue(cfg)

    def test_read_cfg(self):
        """Read test"""

        cfg = init_cfg_obj()

        self.assertRaises(ConfigurationError, cfg.read)

    def test_empty_config(self):
        """Test empty (valid but useless) configuration"""

        filename = '/tmp/empty.cfg'

        section = 'azure'

        try:
            cfg = create_empty_cfg(filename, section)

            cfg = init_cfg_obj(filename, section)
        finally:
            try:
                os.unlink(filename)
            except IOError as exc:
                pass

    def test_get_required_option(self):
        """Check for non-existent required option"""

        section = 'azure'

        cfg = create_empty_cfg('/tmp/test.cfg', section)

        cfg.read()

        self.assertRaises(ConfigurationError,
                          cfg.get_required_option, section, 'blah')
