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


class tortuga_kit_azureadapter::management {
  include tortuga_kit_azureadapter::config

  $compdescr = "management-${tortuga_kit_azureadapter::config::major_version}"

  contain tortuga_kit_azureadapter::management::package
  contain tortuga_kit_azureadapter::management::install
  contain tortuga_kit_azureadapter::management::config

  # Notify Tortuga web service to restart after installing Azure adapter
  Class['tortuga_kit_azureadapter::management::install']
    ~> Class['tortuga_kit_base::installer::webservice::server']
}

class tortuga_kit_azureadapter::management::package {
}

class tortuga_kit_azureadapter::management::install {
  require tortuga_kit_azureadapter::management::package

  include tortuga_kit_azureadapter::config

  tortuga::run_post_install { 'tortuga_kit_azureadapter_management_post_install':
    kitdescr  => $tortuga_kit_azureadapter::config::kitdescr,
    compdescr => $tortuga_kit_azureadapter::management::compdescr,
  }
}

class tortuga_kit_azureadapter::management::config {
  require tortuga_kit_azureadapter::management::install

  include tortuga::config
}
