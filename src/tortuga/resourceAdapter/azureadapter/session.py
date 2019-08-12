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

from typing import Optional

from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.blob import ContainerClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient


class AzureSession:
    """Object holding session information
    """
    def __init__(self, config: Optional[dict] = None):
        """
        :raises ConfigurationError:
        """

        self.config = config or {}

        self.credentials: Optional[ServicePrincipalCredentials] = None

        # Handle to Azure service management session
        # self.session = None

        self.compute_client: Optional[ComputeManagementClient] = None
        self.storage_mgmt_client: Optional[StorageManagementClient] = None
        self.network_client: Optional[NetworkManagementClient] = None
        self.container_client: Optional[ContainerClient] = None

        # Initialize Azure service management session
        self.__init_session()

    def __init_session(self):
        subscription_id = self.config['subscription_id']

        self.credentials = self.__get_credentials()

        self.compute_client = ComputeManagementClient(
            self.credentials, subscription_id)

        self.network_client = NetworkManagementClient(
            self.credentials, subscription_id)

        self.storage_mgmt_client = StorageManagementClient(
            self.credentials, subscription_id)

        storageaccount = self.config.get('storageaccount', None)
        container = self.config.get('container', None)
        if storageaccount and container:
            account_url = "https://{}.blob.core.windows.net/".format(
                storageaccount
            )
            self.container_client = ContainerClient(account_url, container,
                                                    self.credentials)

    def __get_credentials(self):
        return ServicePrincipalCredentials(
            client_id=self.config['client_id'],
            secret=self.config['secret'],
            tenant=self.config['tenant_id']
        )
