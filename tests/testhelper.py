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

import configparser

from tortuga.resourceAdapter import azureadapter


def init_cfg_obj(filename='nonexistent.cfg', section='nonexistent'):
    return azureadapter.ResourceAdapterConfigParser(filename, section)


def create_empty_cfg(filename, section):
    cfg = configparser.ConfigParser()

    cfg.add_section('resource-adapter')
    cfg.add_section(section)

    with open(filename, 'w') as fp:
        cfg.write(fp)

    return init_cfg_obj(filename, section)
