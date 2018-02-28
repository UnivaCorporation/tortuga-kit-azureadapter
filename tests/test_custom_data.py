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

from tortuga.resourceAdapter.azureadapter import Azureadapter
from tortuga.db.dbManager import DbManager
from tortuga.db.nodesDbHandler import NodesDbHandler


adapter = Azureadapter()

# adapter_configuration_profile = 'ubuntu'

azure_session = adapter._Azureadapter__get_session()

# print azure_session.config

# print adapter._Azureadapter__get_cloud_init_custom_data(azure_session.config)

session = DbManager().openSession()

node = NodesDbHandler().getNode(session, 'compute-06-rfzxy')

print(adapter._Azureadapter__get_cloud_init_script_custom_data(azure_session.config, node))
