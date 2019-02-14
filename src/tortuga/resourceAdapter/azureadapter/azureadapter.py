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

import base64
import datetime
import itertools
import os.path
import random
from typing import Any, Dict, Generator, List, NoReturn, Optional, Tuple, Union

from jinja2 import Environment, FileSystemLoader
from sqlalchemy.orm.session import Session

import gevent
import gevent.lock
import gevent.queue
from azure.common import AzureMissingResourceHttpError
from azure.storage.blob import BlockBlobService
from msrestazure import azure_exceptions
from tortuga.db.models.hardwareProfile import HardwareProfile
from tortuga.db.models.instanceMapping import InstanceMapping
from tortuga.db.models.instanceMetadata import InstanceMetadata
from tortuga.db.models.nic import Nic
from tortuga.db.models.node import Node
from tortuga.db.models.softwareProfile import SoftwareProfile
from tortuga.db.nodesDbHandler import NodesDbHandler
from tortuga.exceptions.configurationError import ConfigurationError
from tortuga.exceptions.nodeNotFound import NodeNotFound
from tortuga.exceptions.resourceNotFound import ResourceNotFound
from tortuga.node import state
from tortuga.resourceAdapter.resourceAdapter import \
    DEFAULT_CONFIGURATION_PROFILE_NAME, ResourceAdapter

from .exceptions import AzureOperationTimeout
from .helper import AZURE_SETTINGS_DICT, _get_encoded_list, parse_tags
from .session import AzureSession


AZURE_ASYNC_OP_TIMEOUT = 900


class AzureAdapter(ResourceAdapter):
    __adaptername__ = 'azure'

    settings = AZURE_SETTINGS_DICT

    def __init__(self, addHostSession: Optional[str] = None) -> None:
        super().__init__(addHostSession=addHostSession)

        self._nodesDbHandler = NodesDbHandler()

    def start(self, addNodesRequest, dbSession, dbHardwareProfile,
              dbSoftwareProfile=None):
        """
        Create Azure virtual machine to map to a Tortuga node.

        Called when nodes are added to Tortuga.

        """

        self._logger.debug(
            'start(): addNodesRequest=[%s], dbSession=[%s],'
            ' dbHardwareProfile=[%s], dbSoftwareProfile=[%s]',
            addNodesRequest, dbSession, dbHardwareProfile,
            dbSoftwareProfile
        )

        start_time = datetime.datetime.utcnow()

        nodes = self.__add_active_nodes(
            addNodesRequest,
            dbSession,
            dbHardwareProfile,
            dbSoftwareProfile
        )

        if len(nodes) < addNodesRequest['count']:
            self._logger.warning(
                '%s node(s) requested, only %s launched successfully',
                addNodesRequest['count'], len(nodes)
            )

        # This is a necessary evil for the time being, until there's
        # a proper context manager implemented.
        self.addHostApi.clear_session_nodes(nodes)

        end_time = datetime.datetime.utcnow()

        time_delta = end_time - start_time

        self._logger.debug(
            'start() session [%s] completed in %.2f seconds',
            self.addHostSession,
            time_delta.seconds + time_delta.microseconds / 1000000.0
        )

        return nodes

    def __create_node(self, session: Session, hardwareprofile: HardwareProfile,
                      softwareprofile: SoftwareProfile,
                      override_dns_domain: Optional[str] = None) -> Node:
        """
        Create node record
        """
        name = self.addHostApi.generate_node_name(
            session,
            hardwareprofile.nameFormat,
            randomize=True,
            dns_zone=self.private_dns_zone)

        if not override_dns_domain and '.' in self.installer_public_hostname:
            # Extract host name from generated node name and append
            # DNS domain from installer host name

            dns_zone = self.installer_public_hostname.split('.', 1)[1]

            generated_hostname = name.split('.', 1)[0]

            name = '{}.{}'.format(generated_hostname, dns_zone)
        elif override_dns_domain:
            # Strip 'default' DNS domain suffix from generated node name
            hostname, domain = name.split('.', 1)

            if domain != override_dns_domain:
                # Handle adapter-specific DNS domain (ie. multi-cloud)
                name = '{}.{}'.format(hostname, override_dns_domain)

        return Node(
            name=name,
            state=state.NODE_STATE_LAUNCHING,
            hardwareprofile=hardwareprofile,
            softwareprofile=softwareprofile,
            addHostSession=self.addHostSession,
        )

    def __create_nodes(self, count: int, session: Session,
                       hardwareprofile: HardwareProfile,
                       softwareprofile: SoftwareProfile,
                       configDict: dict, *,
                       metadata: Optional[dict] = None) -> List[Node]: \
            # pylint: disable=unused-argument
        """
        Create nodes records
        """

        dns_domain = None \
            if not configDict.get('override_dns_domain', None) \
            else configDict['dns_domain']

        nodes: List[Node] = []

        for _ in range(count):
            node = self.__create_node(
                session,
                hardwareprofile,
                softwareprofile,
                override_dns_domain=dns_domain
            )

            if metadata and 'vcpus' in metadata:
                node.vcpus = metadata['vcpus']

            nodes.append(node)

        return nodes

    def process_config(self, config: Dict[str, Any]):
        #
        # Get the SSH key
        #
        config['ssh_key_value'] = \
            self.__get_ssh_public_key(config.get('ssh_key_value'))

        #
        # Validate the image/image_urn
        #
        if 'image_urn' in config:
            try:
                publisher, offer, sku, version = \
                    config['image_urn'].split(':', 4)
                config['image_reference'] = {
                    'publisher': publisher,
                    'offer': offer,
                    'sku': sku,
                    'version': version,
                }

            except ValueError:
                raise ConfigurationError(
                    'Malformed "image_urn" in adapter configuration')

        #
        # Managed disks
        #
        if 'image' in config:
            #
            # VMs created from images must use managed disks
            #
            config['use_managed_disks'] = True

        if not config.get('use_managed_disks'):
            if 'storage_account' not in config:
                raise ConfigurationError(
                    'Azure storage account must be specified when using'
                    ' unmanaged disks')

        if 'ssd' in config and not config.get('use_managed_disks'):
            self._logger.warning(
                'Ignoring "ssd" setting; must be set in storage account'
                ' settings'
            )

        #
        # Parse tags
        #
        if config.get('tags'):
            config['tags'] = parse_tags(config['tags'])

        #
        # DNS domain
        #
        config['dns_domain'] = config['dns_domain'] \
            if 'dns_domain' in config else self.private_dns_zone

        #
        # DNS search
        #
        if 'dns_search' not in config:
            #
            # If not specified, use 'dns_domain' as the default
            # DNS search when 'override_dns_domain' is enabled
            #
            if config.get('override_dns_domain'):
                config['dns_search'] = config['dns_domain']
            #
            # Otherwise default to DNS domain of installer
            #
            else:
                result = self.installer_public_hostname.split('.', 1)
                config['dns_search'] = result[1] if len(result) == 2 else None

        #
        # DNS nameservers
        #
        if config.get('dns_nameservers') is None:
            config['dns_nameservers'] = [
                self.installer_public_ipaddress,
            ]

    def __add_active_nodes(self, addNodesRequest, dbSession,
                           hardwareprofile, softwareprofile):
        """
        Returns list of Node

        Raises:
            ResourceNotFound
            OperationFailed
            NetworkNotFound
        """

        cfgname = addNodesRequest.get('resource_adapter_configuration')
        if cfgname is None or cfgname == DEFAULT_CONFIGURATION_PROFILE_NAME:
            # use default resource adapter configuration, if set
            cfgname = hardwareprofile.default_resource_adapter_config.name \
                if hardwareprofile.default_resource_adapter_config else None

        configDict = self.getResourceAdapterConfig(cfgname)

        azure_session = AzureSession(config=configDict)

        # This bit of ugliness sets the configuration item 'ssh_key_value'
        # to either the user-provided override value or the default
        # (/root/.ssh/id_rsa.pub)
        if 'extra_args' in addNodesRequest and \
                'ssh-key-value' in addNodesRequest['extra_args']:
            # Override default value with command-line argument
            azure_session.config['ssh_key_value'] = \
                self.__get_ssh_public_key(
                    addNodesRequest['extra_args']['ssh-key-value'])

        if 'cloud_init_script_template' in azure_session.config:
            self._logger.info(
                'Using cloud-init template [%s]',
                azure_session.config['cloud_init_script_template']
            )
        elif 'user_data_script_template' in azure_session.config:
            self._logger.info(
                'Using custom data script template [%s]',
                azure_session.config['user_data_script_template']
            )

        if azure_session.config['use_managed_disks'] and \
                'storage_account' in azure_session.config:
            self._logger.info(
                'Ignoring \'storage_account\' setting'
                ' because VM image is being used.')

        vcpus = self.get_core_count(
            azure_session,
            azure_session.config['location'],
            azure_session.config['size'],
        )

        # Precreate node records
        nodes = self.__create_nodes(
            addNodesRequest['count'],
            dbSession,
            hardwareprofile,
            softwareprofile,
            azure_session.config,
            metadata={
                'vcpus': vcpus,
            }
        )

        # Commit Nodes to database
        dbSession.add_all(nodes)
        dbSession.commit()

        node_requests = self.__init_node_request_queue(nodes)

        tags = {
            'tortuga_softwareprofile': softwareprofile.name,
            'tortuga_hardwareprofile': hardwareprofile.name,
            'tortuga_installer_hostname': self.installer_public_hostname,
            'tortuga_installer_ipaddress': self.installer_public_ipaddress,
        }

        addNodesRequest['tags'] = dict(
            list(tags.items()) +
            list(azure_session.config['tags'].items())
            if 'tags'in azure_session.config and
            azure_session.config['tags'] else [])

        # Launch jobs in parallel
        launch_jobs = [
            gevent.spawn(
                self.__launch_vm, addNodesRequest, azure_session,
                dbSession, node_request) for node_request in node_requests]

        # Create queue used for waiting on launch VMs
        wait_queue = gevent.queue.JoinableQueue()

        # Create workers
        num_wait_for_instance_workers = min(len(launch_jobs), 20)

        for _ in range(num_wait_for_instance_workers):
            gevent.spawn(
                self.__wait_for_instance_greenlet, wait_queue,
                dbSession, azure_session)

        # Enqueue VM launch results as they become available
        for launch_job in gevent.iwait(launch_jobs):
            async_vm_creation, node_request = launch_job.get()

            if async_vm_creation is None:
                # Instance failed to launch
                node_request['node'].state = state.NODE_STATE_ERROR
                dbSession.commit()

                continue

            # Update instance cache
            node = node_request['node']
            vm_name = get_vm_name(node.name)

            adapter_cfg = self.load_resource_adapter_config(
                dbSession,
                addNodesRequest.get('resource_adapter_configuration')
            )

            node.instance = InstanceMapping(
                instance_metadata=[
                    InstanceMetadata(key='vm_name', value=vm_name),
                ],
                resource_adapter_configuration=adapter_cfg,
            )

            wait_queue.put((async_vm_creation, node_request))

        # Wait for VMs
        wait_queue.join()

        return self.__process_completed_node_requests(
            dbSession, azure_session, node_requests)

    def __process_completed_node_requests(self, dbSession, azure_session,
                                          node_requests):

        # All node create requests are now complete, check for failure

        exc = None

        for node_request in node_requests:
            if 'exception' in node_request:
                exc = node_request['exception']
                break

        else:
            # All VMs launched successfully!
            return [node_['node'] for node_ in node_requests]

        # Operation failed, cleanup...

        self._logger.error(
            'Error launching requested instances. Cleaning up...')

        successful_node_requests = []
        failed_node_requests = []

        for node_request in node_requests:
            if 'status' in node_request and \
                    node_request['status'] == 'launched':
                successful_node_requests.append(node_request)
            else:
                failed_node_requests.append(node_request)

        # Clean up vms
        self.__cleanup_after_failed_create(
            dbSession, azure_session, failed_node_requests)

        # Push the exception up the stack
        if not successful_node_requests:
            # Raise an exception to terminate add nodes opeation
            raise exc  # pylint: disable=raising-bad-type

        # Pertial success- return list of successfully launched VMs
        return [node_['node'] for node_ in successful_node_requests]

    def __wait_for_instance_greenlet(self, wait_queue, dbSession,
                                     azure_session):
        while True:
            async_vm_creation, node_request = wait_queue.get()

            try:
                node = node_request['node']
                vm_name = get_vm_name(node.name)

                self._logger.debug('Waiting for VM [%s]...', vm_name)

                start_time = datetime.datetime.utcnow()

                self.__wait_for_vm_completion(
                    azure_session, node_request, async_vm_creation)

                time_delta = datetime.datetime.utcnow() - start_time

                self._logger.debug(
                    'VM [%s] launched successfully after %s seconds',
                    vm_name,
                    time_delta.seconds + time_delta.microseconds / 1000000.0
                )

                # Update node state
                node.state = state.NODE_STATE_PROVISIONED
                self.fire_provisioned_event(node)
                dbSession.commit()

                node_request['status'] = 'launched'
            except Exception as exc:
                # Azure operataion failed
                node_request['status'] = 'failed'
                node_request['exception'] = exc
            finally:
                wait_queue.task_done()

    def __cleanup_after_failed_create(self, dbSession, azure_session,
                                      node_requests):
        reqs = [gevent.spawn(self.__azure_delete_vm_req, req)
                for req in self.__iter_cleanup_delete_requests(
                    node_requests, azure_session)]

        self.__common_delete_nodes(reqs)

        for node_request in node_requests:
            # Remove Nodes record and associated nics from database
            self.__cleanup_node(dbSession, node_request['node'])

            dbSession.commit()

    def __iter_cleanup_delete_requests(self, node_requests, azure_session):
        for node_request in node_requests:
            yield self.__init_delete_request(
                node_request['node'],
                get_vm_name(node_request['node'].name),
                azure_session)

    def __init_delete_request(self, node, vm_name, azure_session): \
            # pylint: disable=no-self-use
        return {
            'node': node,
            'vm_name': vm_name,
            'azure_session': azure_session,
        }

    def __cleanup_node(self, session, node): \
            # pylint: disable=no-self-use
        """Remove Nodes and associated nics from database"""

        # Ensure session node cache entry is removed for failed launch
        self.addHostApi.clear_session_node(node)

        for nic in node.nics:
            session.delete(nic)

        session.delete(node)

    def __launch_vm(self, addNodesRequest, azure_session,
                    db_session: Session, node_request: dict):
        node = node_request['node']

        vm_name = get_vm_name(node.name)

        self._logger.info('Launching VM [%s]', vm_name)

        custom_data = self.__get_custom_data(azure_session, node)

        try:
            with gevent.Timeout(
                    azure_session.config['launch_timeout'], TimeoutError):
                async_vm_creation = self.__create_vm(
                    azure_session, db_session, node, custom_data=custom_data,
                    tags=addNodesRequest['tags'])

            return async_vm_creation, node_request
        except (azure_exceptions.CloudError, TimeoutError) as exc:
            node_request['status'] = 'failed'
            node_request['exception'] = exc

            if isinstance(exc, azure_exceptions.CloudError):
                self._logger.error(
                    'Error launching VM [%s]: %s',
                    vm_name, exc.message
                )

            if isinstance(exc, TimeoutError):
                self._logger.error('Timed out launching VM [%s]', vm_name)

            # Clean up
            self.__delete_nic(azure_session, vm_name)

        return None, node_request

    def __delete_nic(self, azure_session, vm_name):
        try:
            self.__azure_delete_network_interface(
                azure_session, '{0}-nic'.format(vm_name))
        except azure_exceptions.CloudError as exc2:
            self._logger.debug(
                'Error attempting to remove nic for failed'
                ' VM: %s', exc2.message
            )

    def __wait_for_vm_completion(self, azure_session, node_request,
                                 async_vm_creation):
        # 'max_sleep_time' is the maximum number of seconds to wait
        # before polling. 'sleep_interval' is the number of seconds
        # between requests.
        # TODO: ultimately these may become tunables
        max_sleep_time = 15000
        sleep_interval = 2000

        total_wait_time = 0

        # Poll VM state; break out when provisioning state is "Succeeded"
        for retries in itertools.count(0):
            if async_vm_creation.done():
                break

            if retries == 0:
                # first loop iteration; wait for longer time while Azure
                # creates resources.
                sleeptime = 15
            else:
                # Use fuzzed exponential backoff algorithm to stagger
                # API requests
                temp = min(max_sleep_time, sleep_interval * 2 ** retries)

                sleeptime = (temp / 2 + random.randint(0, temp / 2)) / 1000.0

            # TODO: implement timeout checking here

            total_wait_time += sleeptime

            vm_name = get_vm_name(node_request['node'].name)

            self._logger.debug(
                'Waiting %.2f seconds for VM [%s]', sleeptime, vm_name
            )

            gevent.sleep(sleeptime)

            try:
                vm = self.__azure_get_vm(azure_session, vm_name)

                if vm.provisioning_state == 'Succeeded':
                    break
            except azure_exceptions.CloudError as poll_exc:
                if poll_exc.status_code == 404:
                    # Silently ignore "not found" error when creating; it
                    # may take several seconds for the VM to be registered
                    # with the system.
                    continue

                raise

        # async_vm_creation.wait() (instance of AzureOperationPoller)
        # can raise CloudError
        async_vm_creation.wait()

    def __init_node_request_queue(self, nodes): \
            # pylint: disable=no-self-use
        """Construct a lookup table of instances, nodes, and VPN IDs,
        keyed on the instance
        """

        node_request_queue = []

        for node in nodes:
            node_request = {
                'node': node,
                'status': 'pending',
            }

            node_request_queue.append(node_request)

        return node_request_queue

    def __get_custom_data(self, azure_session, node):
        self._logger.debug(
            '__get_custom_data(): node=[%s]', node.name
        )

        if 'cloud_init_script_template' in azure_session.config:
            return self.__get_cloud_init_custom_data(azure_session.config)
        elif 'user_data_script_template' in azure_session.config:
            return self.__get_bootstrap_script(
                azure_session.config, node)

        return None

    def __get_cloud_init_custom_data(self, configDict):
        """Process cloud-init template using Jinja2 templating language"""

        srcpath, srcfile = os.path.split(
            configDict['cloud_init_script_template'])

        env = Environment(loader=FileSystemLoader(srcpath))

        template = env.get_template(srcfile)

        tmpl_vars = self.__get_common_tmpl_vars(configDict)

        tmpl_vars.update({
            'installer': self.installer_public_hostname,
            'installer_ip_address': self.installer_public_ipaddress,
        })

        return template.render(tmpl_vars)

    def __get_common_tmpl_vars(self, configDict: dict) -> dict:
        """Returns dict containing common template variables shared between
        user-data script template and cloud-init template.
        """
        return {
            'override_dns_domain':
            configDict.get('override_dns_domain', False),
            'dns_domain': configDict['dns_domain'],
            'dns_nameservers':
            _get_encoded_list(configDict['dns_nameservers']),
            'dns_search': configDict['dns_search'],
        }

    def __get_bootstrap_script(self, configDict, node) -> str:
        """Generate node-specific custom data from template"""

        self._logger.info(
            'Using cloud-init script template [%s]',
            configDict['user_data_script_template']
            )

        installerIp = node.hardwareprofile.nics[0].ip \
            if node.hardwareprofile.nics else self.installer_public_ipaddress

        with open(configDict['user_data_script_template']) as fp:
            result = ''

            settings_dict = self.__get_common_tmpl_vars(configDict)

            settings_dict.update({
                'installerHostName': self.installer_public_hostname,
                'installerIp': installerIp,
                'adminport': self._cm.getAdminPort(),
                'cfmuser': self._cm.getCfmUser(),
                'cfmpassword': self._cm.getCfmPassword(),
            })

            for inp in fp.readlines():
                if inp.startswith('### SETTINGS'):
                    result += '''\
installerHostName = '%(installerHostName)s'
installerIpAddress = '%(installerIp)s'
port = %(adminport)d
cfmUser = '%(cfmuser)s'
cfmPassword = '%(cfmpassword)s'

override_dns_domain = %(override_dns_domain)s
dns_search = '%(dns_search)s'
dns_domain = '%(dns_domain)s'
dns_nameservers = %(dns_nameservers)s
''' % (settings_dict)
                else:
                    result += inp

        return result

    def __create_vm(self, session, db_session: Session, node: Node,
                    custom_data: Optional[Union[str, None]] = None,
                    tags=None) -> NoReturn:
        """Raw Azure create VM operation"""

        vm_name = get_vm_name(node.name)

        self._logger.debug('__create_vm(): vm_name=[%s]', vm_name)

        # Create network interface
        nic = self.create_nic(session, vm_name)

        # Associate internal nic with node
        node.nics.append(
            Nic(ip=nic.ip_configurations[0].private_ip_address, boot=True))

        # ...and commit to database
        db_session.commit()

        # Call pre-add-host to set up DNS record
        self._pre_add_host(
            node.name,
            node.hardwareprofile.name,
            node.softwareprofile.name,
            nic.ip_configurations[0].private_ip_address)

        # Create VM "template"
        vm_parameters = self.create_vm_parameters(
            session, nic.id, vm_name, custom_data=custom_data, tags=tags)

        # Create VM
        return session.compute_client.virtual_machines.create_or_update(
            session.config['resource_group'], vm_name, vm_parameters)

    def create_vm_parameters(self, session, nic_id, vm_name,
                             custom_data=None, tags=None): \
            # pylint: disable=no-self-use
        """Create the VM parameters structure.
        """

        ssh_public_key = session.config['ssh_key_value']

        vhd_name = vm_name

        storage_profile = {
            'os_disk': {
                'os_type': 'Linux',
                'name': '%s-os-disk' % (vm_name),
                'caching': 'ReadWrite',
                'create_option': 'fromImage',
            }
        }

        if session.config['use_managed_disks']:
            # Managed disk

            if session.config['ssd']:
                storage_profile['os_disk']['managed_disk'] = {
                    'storage_account_type': 'Premium_LRS',
                }
        else:
            # Regular (unmanaged) disk

            # Build unique URI for VHD
            vhd_uri = 'https://{}.blob.core.windows.net/vhds/{}.vhd'.format(
                session.config['storage_account'], vhd_name)

            storage_profile['os_disk']['vhd'] = {
                'uri': vhd_uri,
            }

        if 'image_reference' in session.config:
            storage_profile['image_reference'] = \
                session.config['image_reference']
        else:
            # Look up id of image
            image_id = session.compute_client.images.get(
                session.config['resource_group'], session.config['image']).id

            storage_profile['image_reference'] = {
                'id': image_id,
            }

            if 'storage_account_type' in session.config and \
                    session.config['storage_account_type']:
                storage_profile['os_disk']['managed_disk'] = {
                    'storage_account_type':
                    session.config['storage_account_type']
                }

        result = {
            'location': session.config['location'],
            'os_profile': {
                'computer_name': vm_name,
                'admin_username': session.config['default_login'],
                'linux_configuration': {
                    'disable_password_authentication': True,
                    'ssh': {
                        'public_keys': [
                            {
                                'path': '/home/%s/.ssh/authorized_keys' % (
                                    session.config['default_login']),
                                'key_data': ssh_public_key,
                            }
                        ],
                    },
                },
            },
            'hardware_profile': {
                'vm_size': session.config['size']
            },
            'storage_profile': storage_profile,
            'network_profile': {
                'network_interfaces': [{
                    'id': nic_id,
                    'primary': True,
                }]
            },
        }

        if tags:
            result['tags'] = tags

        if custom_data is not None:
            result['os_profile']['custom_data'] = \
                base64.b64encode(custom_data.encode()).decode()

        return result

    def __get_ssh_public_key(self, ssh_key_value=None):
        """Extract filename or ssh key from 'ssh_key_value', if provided.
        If None, use default ssh key (/root/.ssh/id_rsa.pub).

        Raises:
            ConfigurationError
        """

        if not ssh_key_value:
            # Default to root user's ssh public key
            ssh_key_value = '/root/.ssh/id_rsa.pub'
        else:
            # Use command-line override for public ssh key
            if not ssh_key_value.startswith('/'):
                if not ssh_key_value.startswith('ssh-'):
                    raise ConfigurationError(
                        'Public ssh key appears to be malformed')

                return ssh_key_value

        if not os.path.exists(ssh_key_value):
            errmsg = 'SSH key file [{}] does not exist'.format(
                ssh_key_value)

            self._logger.error(errmsg)

            raise ConfigurationError(errmsg)

        self._logger.debug('Reading ssh public key [%s]', ssh_key_value)

        with open(ssh_key_value) as fp:
            ssh_public_key = fp.read()

        return ssh_public_key

    def create_nic(self, session, vm_name): \
            # pylint: disable=no-self-use
        """
        Raises:
            msrestazure.azure_exceptions.CloudError
        """

        self._logger.debug('Creating network interface for VM [%s]', vm_name)

        subnet = \
            session.network_client.subnets.get(
                session.config['resource_group'],
                session.config['virtual_network_name'],
                session.config['subnet_name'][0])

        network_security_group = \
            session.network_client.network_security_groups.get(
                session.config['resource_group'],
                session.config['security_group'])

        ip_configuration = {
            'name': '%s-ip-config' % (vm_name),
            'subnet': {
                'id': subnet.id,
            },
        }

        if session.config['allocate_public_ip']:
            # TODO: this could fail if public ip address resource limits are
            # reached.
            public_ip_address_creation = \
                session.network_client.public_ip_addresses.create_or_update(
                    session.config['resource_group'],
                    '%s-ip-config' % (vm_name), {
                        'location': session.config['location'],
                        'public_ip_address_version': 'IPv4',
                    })

            public_ip_address = self.__wait_for_async_request(
                public_ip_address_creation, 'create_public_ip',
                max_sleep_time=10000, initial_sleep_time=10000)

            ip_configuration['public_ip_address'] = \
                dict(id=public_ip_address.id)

        async_nic_creation = \
            session.network_client.network_interfaces.create_or_update(
                session.config['resource_group'], '%s-nic' % (vm_name), {
                    'location': session.config['location'],
                    'network_security_group': {
                        'id': network_security_group.id,
                    },
                    'ip_configurations': [ip_configuration],
                })

        return self.__wait_for_async_request(
            async_nic_creation, tag='create_nic', max_sleep_time=10000,
            initial_sleep_time=10000)

    def __azure_get_vm(self, session, vm_name):
        """
        Raises:
            msrestazure.azure_exceptions.CloudError
        """

        self._logger.debug('__azure_get_vm(): vm_name=[%s}]', vm_name)

        return session.compute_client.virtual_machines.get(
            session.config['resource_group'], vm_name)

    def __azure_delete_vhd(self, session, blob_name):
        """
        Raises:
            ResourceNotFound
        """

        self._logger.debug('__azure_delte_vhd(): blob_name=[%s]', blob_name)

        container_name = 'vhds'

        keys = session.storage_mgmt_client.storage_accounts.\
            list_keys(session.config['resource_group'],
                      session.config['storage_account'])

        # TODO: when would there be a need to use anything but the
        # first key?
        key = keys.keys[0]

        block_blob_service = BlockBlobService(
            account_name=session.config['storage_account'],
            account_key=key.value)

        try:
            block_blob_service.delete_blob(container_name, blob_name)
        except AzureMissingResourceHttpError as exc:
            raise ResourceNotFound(exc.message)

    def __azure_delete_managed_disk(self, session, disk_name):
        """
        Returns:
            True, if successful
        """

        # Azure does not raise an exception when attempting to delete a
        # non-existent managed disk.

        result = session.compute_client.disks.delete(
            session.config['resource_group'], disk_name)

        retries = 0
        while retries < 5:
            try:
                total_wait_time = 0
                while total_wait_time < 300 and not result.done():
                    gevent.sleep(5)

                    total_wait_time += 5

                if total_wait_time < 300:
                    # Break out of retry loop
                    break
            except Exception as exc:
                self._logger.warning(
                    'Error attempting to delete managed disk'
                    ' %s: %s', disk_name, exc
                )

                # Wait 10s before reattemping operation
                gevent.sleep(10)

            retries += 1

        if retries == 5:
            self._logger.error(
                'Exceeded retry limit attempting to delete managed'
                ' disk [%s]', disk_name
            )

            return False

        self._logger.info('Managed disk [%s] deleted successfully', disk_name)

        return True

    def __azure_delete_network_interface(self, session, interface_id):
        """Delete network interface and all associated ip configurations

        Raises:
            msrestazure.azure_exceptions.CloudError
        """

        try:
            network_interface_obj = \
                session.network_client.network_interfaces.get(
                    session.config['resource_group'], interface_id)
        except azure_exceptions.CloudError as exc:
            if exc.status_code == 404:
                # Quietly ignore "not found" error
                return

            # Re-raise all other exceptions
            raise

        self._logger.debug('Deleting network interface [%s]', interface_id)

        retries = 0
        while retries < 5:
            total_wait_time = 0

            try:
                delete_network_interface_request = \
                    session.network_client.network_interfaces.delete(
                        session.config['resource_group'], interface_id)

                while total_wait_time < 300 and \
                        not delete_network_interface_request.done():
                    # delete_network_interface_request.wait()

                    gevent.sleep(5)

                    total_wait_time += 5

                if total_wait_time < 300:
                    # Break out of retry loop
                    break
            except Exception:
                # TODO: ensure non-recoverable errors are handled
                self._logger.warning(
                    'Failure attempting to delete network interface'
                    ' %s', interface_id
                )

            retries += 1

            # Wait 10s before reattempting failed delete network interface
            gevent.sleep(10)

        if retries == 5:
            self._logger.error(
                'unable to delete network interface [%s]', interface_id
            )

            return False

        # Iterate over ip configurations, deleting any public ip address
        # configurations
        for ip_configuration in network_interface_obj.ip_configurations:
            if not ip_configuration.public_ip_address:
                # Ignore any interfaces without public ip address
                continue

            self.__azure_delete_ip_configuration(
                session,
                os.path.basename(ip_configuration.public_ip_address.id))

        return True

    def __azure_delete_ip_configuration(self, session, ip_configuration_id):
        """Deletes Azure ip configuration

        Raises:
            msrestazure.azure_exceptions.CloudError
        """

        self._logger.debug(
            '__azure_delete_ip_configuration(): '
            'ip_configuration_id=[%s]', ip_configuration_id
        )

        retries = 0
        while retries < 5:
            total_wait_time = 0

            try:
                delete_ip_configuration_request = \
                    session.network_client.public_ip_addresses.delete(
                        session.config['resource_group'], ip_configuration_id)

                while total_wait_time < 300 and \
                        not delete_ip_configuration_request.done():

                    gevent.sleep(5)

                    total_wait_time += 5

                if total_wait_time < 300:
                    # Break out of retry loop
                    break
            except Exception as exc:
                self._logger.warning(
                    'Failure attempting to delete IP configuration'
                    ' %s: %s', ip_configuration_id, exc
                )

            retries += 1

        if retries == 5:
            return False

        # Success
        self._logger.info(
            'IP configuration [%s] deleted successfully', ip_configuration_id
        )

        return True

    def deleteNode(self, nodes: List[Node]) -> None:
        """Delete Azure VMs associated with nodes"""

        reqs = []

        # Iterate over nodes requested to be deleted getting vm_name
        # and Azure session
        for node, azure_session, vm_name in \
                self.__iter_vm_name_and_session_tuples(nodes):

            # Initialize delete request
            delete_request = self.__init_delete_request(
                node, vm_name, azure_session)

            # Perform pre-delete operation
            self.__pre_delete_node(node, azure_session)

            # Spawn one greenlet per node being deleted
            reqs.append(gevent.spawn(self.__azure_delete_vm_req,
                                     delete_request))

        # Complete delete request
        self.__common_delete_nodes(reqs)

    def __common_delete_nodes(self, reqs):
        wait_queue = gevent.queue.JoinableQueue()

        # Spawn worker greenlets to wait on async delete requests
        for _ in range(len(reqs)):
            gevent.spawn(self.__complete_delete_request, wait_queue)

        # Iterate over async delete requests
        for req in gevent.iwait(reqs):
            delete_request = req.get()

            if 'async_request' in delete_request and \
                    delete_request['async_request'] is None:
                continue

            # Enqueue completed delete requests
            wait_queue.put(delete_request)

        wait_queue.join()

    def __pre_delete_node(self, node, azure_session):
        """no op"""

    def __azure_delete_vm_req(self, req):
        session = req['azure_session']
        vm_name = req['vm_name']

        try:
            # Look up VM (req'd to delete associated resources)
            req['vm'] = self.__azure_get_vm(session, vm_name)

            req['async_request'] = session.compute_client.virtual_machines.\
                delete(req['azure_session'].config['resource_group'], vm_name)
        except azure_exceptions.CloudError as exc:
            if exc.status_code == 404:
                req['async_request'] = None

        return req

    def __complete_delete_request(self, wait_queue):
        while True:
            delete_request = wait_queue.get()

            try:
                vm = delete_request['vm']
                vm_name = delete_request['vm_name']
                session = delete_request['azure_session']

                # process delete_request
                self.__wait_for_async_request(
                    delete_request['async_request'],
                    tag='Deleting VM [{0}]'.format(vm_name),
                    max_sleep_time=15000, initial_sleep_time=30000)

                # Delete associated network interfaces
                for network_interface in \
                        vm.network_profile.network_interfaces:
                    self.__azure_delete_network_interface(
                        session, os.path.basename(network_interface.id))

                # Remove os vhd
                if vm.storage_profile.os_disk.vhd:
                    blob_name = os.path.basename(
                        vm.storage_profile.os_disk.vhd.uri)

                    self._logger.debug(
                        'Deleting [%s] os disk [%s]', vm_name, blob_name
                    )

                    try:
                        self.__azure_delete_vhd(session, blob_name)
                    except ResourceNotFound:
                        self._logger.info(
                            'Azure blob [%s] does not exist', blob_name
                        )
                elif vm.storage_profile.os_disk.managed_disk:
                    disk_name = vm.storage_profile.os_disk.name

                    try:
                        self.__azure_delete_managed_disk(session, disk_name)
                    except ResourceNotFound:
                        self._logger.info(
                            'Managed disk [%s] does not exist', disk_name
                        )

                self._logger.info('VM [%s] deleted', vm_name)
            except Exception as exc:
                self._logger.error('Error deleting VM [%s]: %s', vm_name, exc)
            finally:
                wait_queue.task_done()

    def __wait_for_async_request(self, async_request, tag: str = None,
                                 max_sleep_time: int = 7000,
                                 sleep_interval: int = 2000,
                                 initial_sleep_time: int = 7000):
        """
        Generic routine for waiting on an async Azure request

        :param max_sleep_time: maximum sleep time (in milliseconds)
        :param sleep_interval: time between polling intervals (in milliseconds)
        :param initial_sleep_time: initial sleep time (in milliseconds)
        :return: result from async request

        Raise:
            AzureOperationTimeout
        """

        logmsg_prefix = '{0}: '.format(tag) if tag else ''

        total_sleep_time = 0

        for retries in itertools.count(0):
            if async_request.done():
                break

            if retries == 0:
                sleeptime = initial_sleep_time / 1000.0
            else:
                temp = min(max_sleep_time, sleep_interval * 2 ** retries)
                sleeptime = (temp / 2 + random.randint(0, temp / 2)) / 1000.0

            self._logger.debug(
                '%ssleeping %.2f seconds on async request',
                logmsg_prefix, sleeptime
            )

            gevent.sleep(sleeptime)

            total_sleep_time += sleeptime

            if total_sleep_time > AZURE_ASYNC_OP_TIMEOUT:
                raise AzureOperationTimeout(
                    'Timeout exceeded waiting for async operation'
                    ' completion')

        return async_request.result()

    def rebootNode(self, nodes, bSoftReset=False):
        restart_vm_queue = gevent.queue.JoinableQueue()

        # Set up coroutines
        for _ in range(len(nodes) if len(nodes) < 8 else 8):
            gevent.spawn(self.__restart_vm_worker, restart_vm_queue)

        # Enqueue vm reboot requests
        for _, azure_session, vm_name in \
                self.__iter_vm_name_and_session_tuples(nodes):
            restart_vm_queue.put((azure_session, vm_name))

        # Finally, join the queue to complete reboot operations
        restart_vm_queue.join()

    def __restart_vm_worker(self, q):
        """Coroutine for Azure async restart operation"""

        while True:
            try:
                azure_session, vm_name = q.get()

                self._logger.info('Rebooting VM [%s]', vm_name)

                response = \
                    azure_session.compute_client.virtual_machines.restart(
                        azure_session.config['resource_group'], vm_name)

                while not response.done():
                    gevent.sleep(5)

                self._logger.debug(
                    'VM [%s] restart async operation complete', vm_name
                )
            except azure_exceptions.CloudError as exc:
                if exc.status_code == 404:
                    # Quietly ignore "not found" error
                    continue

                self._logger.error('Error restarting VM [%s]', vm_name)
            finally:
                q.task_done()

            continue

    def startupNode(self, nodes, remainingNodeList=[],
                    tmpBootMethod='n'): \
            # pylint: disable=unused-argument
        startup_vm_queue = gevent.queue.JoinableQueue()

        # Set up coroutines
        for _ in range(len(nodes) if len(nodes) < 8 else 8):
            gevent.spawn(self.__start_vm_worker, startup_vm_queue)

        # Enqueue vm reboot requests
        for _, azure_session, vm_name in \
                self.__iter_vm_name_and_session_tuples(nodes):
            # Enqueue shutdown request
            startup_vm_queue.put((azure_session, vm_name))

        # Finally, join the queue to complete reboot operations
        startup_vm_queue.join()

    def __start_vm_worker(self, q):
        while True:
            session, vm_name = q.get()

            try:
                try:
                    self._logger.info('Starting VM [%s]', vm_name)

                    response = \
                        session.compute_client.virtual_machines.start(
                            session.config['resource_group'], vm_name)

                    while not response.done():
                        gevent.sleep(5)

                    self._logger.debug(
                        'VM [%s] async start VM operation complete', vm_name
                    )
                except Exception:
                    self._logger.exception('Error starting VM(s)')

                    raise
            finally:
                q.task_done()

    def shutdownNode(self, nodes, bSoftReset=False):
        shutdown_vm_queue = gevent.queue.JoinableQueue()

        # Set up coroutines
        for _ in range(len(nodes) if len(nodes) < 8 else 8):
            gevent.spawn(self.__power_off_vm_worker, shutdown_vm_queue)

        # Enqueue vm reboot requests
        for _, azure_session, vm_name in \
                self.__iter_vm_name_and_session_tuples(nodes):
            # Enqueue shutdown request
            shutdown_vm_queue.put((azure_session, vm_name))

        # Finally, join the queue to complete reboot operations
        shutdown_vm_queue.join()

    def __power_off_vm_worker(self, q):
        while True:
            session, vm_name = q.get()

            try:
                try:
                    self._logger.info('Powering VM off [%s]', vm_name)

                    response = \
                        session.compute_client.virtual_machines.power_off(
                            session.config['resource_group'], vm_name)

                    while not response.done():
                        gevent.sleep(5)

                    self._logger.debug(
                        'VM [%s] async power off operation complete', vm_name
                    )
                except Exception:
                    self._logger.exception('Error powering off VM(s)')

                    raise
            finally:
                q.task_done()

    def __iter_vm_name_and_session_tuples(self, nodes: List[Node]) \
            -> Generator[Tuple[Node, 'AzureSession', str], None, None]:
        for node in nodes:
            if not node.instance:
                # ignore node records without backing VM that would exist,
                # for example, if a previous deletion attempt failed
                self._logger.warning(
                    'Unable to determine VM for node [%s]', node.name)

                continue

            try:
                azure_session = AzureSession(
                    config=self.get_node_resource_adapter_config(node)
                )
            except ResourceNotFound:
                # Unable to determine resource adapter configuration
                self._logger.error(
                    'Unable to determine resource adapter'
                    ' configuration for node [%s]', node.name
                )

                continue

            # Use the instance cache to determine the VM name
            vm_name = None

            for md in node.instance.instance_metadata:
                if md.key == 'vm_name':
                    vm_name = md.value
                    break
            else:
                self._logger.warning(
                    'Unable to determine VM name for node [%s]', node.name
                )

                continue

            yield node, azure_session, vm_name

    def get_core_count(self, session, location, vm_size, default: int = 1):
        """
        Query VM sizes from Azure
        """

        vm_sizes = list(session.compute_client.virtual_machine_sizes.list(
            location))

        for result in vm_sizes:
            if result.name == vm_size:
                return result.number_of_cores

        # Unable to determine VM size, use default
        self._logger.warning(
            'Unrecognized Azure VM size [%s]. Using default core count %d',
            vm_size, default
        )

        return default

    def get_node_vcpus(self, name: str) -> int:
        """
        Raises:
            ResourceNotFound

        """
        #
        # Default to zero, because if for some reason the node can't be found
        # (i.e. it was deleted in the background), then it will not be using
        # any cpus
        #
        vcpus = 0

        try:
            node = self._nodesDbHandler.getNode(self.session, name)

            session = AzureSession(
                config=self.get_node_resource_adapter_config(node)
            )

            vcpus = session.config.get('vcpus', 0)
            if not vcpus:
                vcpus = self.get_core_count(session,
                                            session.config['location'],
                                            session.config['size'])
        except NodeNotFound:
            pass

        return vcpus

    def _is_component_enabled(self, node: Node, component_name: str,
                              kit_name: str = 'base') -> bool:
        """Helper function used to validate start arguments.
        """
        for component in node.softwareprofile.components:
            if component.name == component_name and \
                    component.kit.name == kit_name:
                return True

        return False

    def validate_start_arguments(self, addNodesRequest: Dict[str, Any],
                                 dbHardwareProfile: HardwareProfile,
                                 dbSoftwareProfile: SoftwareProfile) -> None: \
            # pylint: disable=unused-argument
        """Raise an exception if the dns component is not enabled

        :raises ConfigurationError:
        """
        installer = dbHardwareProfile.nics[0].node \
            if dbHardwareProfile.nics else \
            self._nodesDbHandler.get_installer_node(self.session)

        if not self._is_component_enabled(installer, 'dns'):
            msg = 'DNS component must be enabled for Azure-based compute nodes'

            self._logger.error(msg)

            raise ConfigurationError(msg)


def get_vm_name(name):
    """
    Map node name to VM name by stripping DNS suffix

    """
    return name.split('.', 1)[0]
