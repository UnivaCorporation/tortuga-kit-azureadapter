import colorama
from configparser import ConfigParser
import ipaddress
import json
import re
import secrets
import subprocess
from typing import Dict, List
from urllib.parse import urlparse

from tortuga.db.dbManager import DbManager
from tortuga.exceptions.resourceNotFound import ResourceNotFound
from tortuga.resourceAdapterConfiguration.api import \
    ResourceAdapterConfigurationApi


class APIError(Exception):
    pass


class ResourceAdapterSetup:
    debug = False
    adapter_type = 'azure'

    def __init__(self):
        self._cli_path: str = self._find_cli()

        self._az_account: dict = {}
        self._az_applications: List[dict] = []
        self._az_resource_groups: List[dict] = []
        self._az_role_assignments: List[dict] = []
        self._az_virtual_networks: List[dict] = []
        self._az_network_security_groups: List[dict] = []
        self._az_subnets: List[dict] = []
        self._az_storage_accounts: List[dict] = []
        self._az_vm_sizes: List[dict] = []

        self._selected_application: dict = None
        self._selected_resource_group: dict = None
        self._selected_virtual_network: dict = None
        self._selected_network_security_group: dict = None
        self._selected_subnet: dict = None
        self._selected_storage_account: dict = None
        self._selected_vm_size: dict = None
        self._selected_image: dict = None

        self._run_completed = False

    def format(self, msg: str, *args, **kwargs):
        """
        Formats a message, with color.

        :param str msg:       the message to format
        :param *args:         args to pass to the str.format(...) method
        :param str forecolor: the colorama foreground color to use, defaults
                              to colorama.Fore.GREEN
        :param **kwargs:      kwargs to pass to the str.format(...) method

        :return: the formatted string

        """
        forecolor = colorama.Fore.GREEN
        if 'forecolor' in kwargs:
            forecolor = kwargs.pop('forecolor')

        formatted_args = []
        for arg in args:
            formatted_args.append(
                colorama.Fore.WHITE + str(arg) + forecolor
            )

        formatted_kwargs = {}
        for key, value in kwargs.items():
            formatted_kwargs[key] = \
                colorama.Fore.WHITE + str(value) + forecolor

        formatted_msg = forecolor + colorama.Style.BRIGHT + \
            msg.format(*formatted_args, **formatted_kwargs) + \
            colorama.Style.RESET_ALL

        return formatted_msg

    def format_white(self, msg, *args, **kwargs):
        """
        Formats a string with white as the foreground color. See format()
        for usage details.

        """
        kwargs['forecolor'] = colorama.Fore.WHITE
        return self.format(msg, *args, **kwargs)

    def format_error(self, msg, *args, **kwargs):
        """
        Formats a string with red as the foreground color. See format()
        for usage details.

        """
        kwargs['forecolor'] = colorama.Fore.RED
        return self.format(msg, *args, **kwargs)

    def run(self):
        config: Dict[str, str] = self.get_config()
        self._write_config_to_file(config, 'default')
        self._write_config_to_db(config, 'default')

    def _write_config_to_file(self, adapter_cfg: Dict[str, str],
                              profile: str):
        """
        Writes the resource adapter configuration to a config file in the
        tmp directory.

        :param adapter_cfg Dict[str, str]: the resource adapter configuration
        :param profile:                    the name of the resource adapter
                                           profile

        """
        section = 'resource-adapter' if profile == 'default' else profile
        cfg = ConfigParser()
        cfg.add_section(section)

        for key, value in adapter_cfg.items():
            cfg.set(section, key, value)

        fn = '/tmp/adapter-defaults-{}.conf'.format(self.adapter_type)
        with open(fn, 'w') as fp:
            cfg.write(fp)

        print(self.format('Wrote resource adapter configuration: {}', fn))

    def _write_config_to_db(self, adapter_cfg: Dict[str, str],
                            profile_name: str):
        normalized_cfg = []
        for key, value in adapter_cfg.items():
            normalized_cfg.append({
                'key': key,
                'value': value,
            })

        api = ResourceAdapterConfigurationApi()
        with DbManager().session() as session:
            try:
                api.get(session, self.adapter_type, profile_name)
                print('Updating resource adapter configuration '
                      'profile: {}'.format(profile_name))
                api.update(session, self.adapter_type, profile_name,
                           normalized_cfg)

            except ResourceNotFound:
                print('Creating resource adapter configuration '
                      'profile {}'.format(profile_name))
                api.create(session, self.adapter_type, profile_name,
                           normalized_cfg)

    def _run_cmd(self, cmd: List[str]) -> str:
        """
        Runs a command line program and returns the results.

        :param cmd List[str]: a list of command and arguments
        :return str:          the result

        """
        if self.debug:
            print(' '.join(cmd))

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()

        err = stderr.decode().strip()
        if err:
            raise Exception(err)

        result = stdout.decode().strip()
        if self.debug:
            print(result)

        return result

    def _find_cli(self) -> str:
        """
        Looks for the Azure CLI.

        :return str: the path to the current CLI

        """
        cli_path = self._run_cmd(['which', 'az'])
        if not cli_path:
            raise Exception('Azure CLI not found')

        return cli_path

    def _run_az(self, cmd: List[str]) -> [list, dict]:
        """
        Runs an Azure CLI command and returns the result as a dict.

        :param cmd List[str]: the az command to run

        :return [list, dict]: the command result

        """
        az_cmd = [self._cli_path]
        az_cmd.extend(cmd)

        try:
            result = json.loads(self._run_cmd(az_cmd))
        except Exception as ex:
            if str(ex).startswith('ERROR'):
                raise APIError(str(ex))
            else:
                raise

        return result

    def _get_account(self) -> dict:
        """
        Gets the account info for the current user.

        :return dict: the account info

        """
        print('Getting account information...')

        return self._run_az(['account', 'show'])

    def _get_applications(self) -> List[dict]:
        """
        Gets the list of applications from AD
        :return List[dict]: a list of application data

        """
        print('Getting application list...')

        return self._run_az(['ad', 'app', 'list'])

    def _create_application(self):
        """
        Creates a new Active Directory application.

        :return dict: the created application

        """
        name = ''
        while not name:
            name = input(self.format('Application name: '))
            name = name.strip()

        url = ''
        while not url_valid(url):
            url = input(self.format('Application URL (a unique URI): '))

        password = secrets.token_urlsafe()

        print('Creating application...')

        try:
            application = self._run_az([
                'ad', 'app', 'create',
                '--display-name', name,
                '--native-app', 'false',
                '--identifier-uris', url,
                '--key-type', 'Password',
                '--password', password
            ])
            #
            # Attach password to the application object so we can refer to
            # it later.
            #
            application['password'] = password
            self._az_applications.append(application)

        except APIError as e:
            print(self.format_error(str(e)))
            return self._create_application()

        #
        # Create the Service Principal
        #
        print('Creating service principal...')

        self._run_az([
            'ad', 'sp', 'create',
            '--id', application['appId']

        ])

        print(self.format('The following application API password was '
              'generated: {}', password))

        return application

    def _get_resource_groups(self):
        """
        Gets the list of resource groups from AD
        :return List[dict]: a list of resource group data

        """
        print('Getting resource groups...')

        return self._run_az(['group', 'list'])

    def _create_resource_group(self):
        """
        Creates a new resource group.

        :return dict: the created resource group

        """
        name = ''
        while not name:
            name = input(self.format('Resource group name: '))
            name = name.strip()

        location = ''
        while not location:
            location = input(self.format('Location: '))
            location = location.strip().lower()

        print('Creating resource group...')

        try:
            resource_group = self._run_az([
                'group', 'create',
                '--name', name,
                '--location', location
            ])
            self._az_resource_groups.append(resource_group)

        except APIError as e:
            print(self.format_error(str(e)))
            return self._create_resource_group()

        return resource_group

    def _get_role_assignments(self):
        """
        Gets the current list of role assignments for the selected
        application in the selected resource group.

        :return List[dict: a list of role assignments

        """
        print('Getting role assignments...')

        return self._run_az([
            'role', 'assignment', 'list',
            '--assignee', self._selected_application['appId'],
            '--resource-group', self._selected_resource_group['name']
        ])

    def _check_role_assignments(self):
        """
        Ensures that the application has the correct privileges in the
        resource group.

        """
        print(self.format_white('----------'))

        if not len(self._az_role_assignments):
            print(
                self.format(
                    'The {} application has no roles assigned in '
                    'in the {} resource group.\n',
                    self._selected_application['displayName'],
                    self._selected_resource_group['name']
                )
            )
            print(
                self.format_white(
                    '[1] Assign the application the Owner role in the '
                    'resource group'
                )
            )
            print(
                self.format_white(
                    '[2] I will assign the application a role myself in the '
                    'Azure portal\n')
            )

            options = ['1', '2']
            selected = ''
            while selected not in options:
                selected = input(self.format('Select an option: '))
                selected = selected.strip().lower()

            if selected == '1':
                self._assign_owner_role()

        else:
            print(
                self.format(
                    'The {} application has the following roles assigned in '
                    'in the {} resource group:\n',
                    self._selected_application['displayName'],
                    self._selected_resource_group['name']
                )
            )

            for assignment in self._az_role_assignments:
                print(
                    self.format_white(
                        '    - {}', assignment['roleDefinitionName']
                    )
                )

            print(
                self.format(
                    '\nThese role(s) may or may-not have sufficient'
                    'privileges to create resources in the resource group. '
                    'If you run into permissions problems, you may need to '
                    'assign additional roles to the application in the Azure '
                    'console.'
                )
            )

            input(self.format('\nPress return to continue...'))

    def _assign_owner_role(self) -> dict:
        """
        Assigns the selected application the Owner role in the selected
        resource group.

        :return dict: the role assignment

        """
        print('Assigning role...')

        return self._run_az([
            'role', 'assignment', 'create',
            '--assignee',  self._selected_application['appId'],
            '--role', 'Owner',
            '--resource-group', self._selected_resource_group['name']
        ])

    def _get_virtual_networks(self) -> List[dict]:
        """
        Gets the list of virtual networks for the selected resource group.

        :return List[dict]: a list of virtual networks

        """
        print('Getting virtual networks...')

        return self._run_az([
            'network', 'vnet', 'list',
            '--resource-group', self._selected_resource_group['name']
        ])

    def _create_virtual_network(self) -> dict:
        """
        Creates a new virtual network.

        :return dict: the created virtual network

        """
        name = ''
        while not name:
            name = input(self.format('Virtual network name: '))
            name = name.strip()

        print('Creating virtual network...')

        try:
            virtual_network = self._run_az([
                'network', 'vnet', 'create',
                '--name', name,
                '--location', self._selected_resource_group['location'],
                '--resource-group', self._selected_resource_group['name']
            ])
            self._az_virtual_networks.append(virtual_network)

        except APIError as e:
            print(self.format_error(str(e)))
            return self._create_virtual_network()

        return virtual_network

    def _get_network_security_groups(self) -> List[dict]:
        """
        Gets a list of network security groups for the selected resource
        group.

        :return List[dict]: a list of network security groups

        """
        print('Getting network security groups...')

        return self._run_az([
            'network', 'nsg', 'list',
            '--resource-group', self._selected_resource_group['name']
        ])

    def _create_network_security_group(self) -> dict:
        """
        Creates a new network security group.

        :return dict: the created network security group

        """
        name = ''
        while not name:
            name = input(self.format('Network security group name: '))
            name = name.strip()

        #
        # Create the security group
        #
        print('Creating network security group...')

        try:
            network_security_group = self._run_az([
                'network', 'nsg', 'create',
                '--name', name,
                '--location', self._selected_resource_group['location'],
                '--resource-group', self._selected_resource_group['name']
            ])
            self._az_network_security_groups.append(network_security_group)

        except APIError as e:
            print(self.format_error(str(e)))
            return self._create_network_security_group()

        #
        # Allow SSH on security group
        #
        print('Enabling inbound SSH (port 22) on network security group...')

        network_security_group = self._run_az([
            'network', 'nsg', 'rule', 'create',
            '--nsg-name', name,
            '--resource-group', self._selected_resource_group['name'],
            '--name', 'ssh',
            '--priority', '100',
            '--destination-address-prefix', '*',
            '--destination-port-range', '22',
            '--access', 'Allow',
            '--protocol', 'Tcp',
            '--description', 'Allow incoming ssh'
        ])

        return network_security_group

    def _get_subnets(self) -> List[dict]:
        """
        Gets a list of subnets in selected resource group.

        :return List[dict]: a list of subnets

        """
        print('Getting subnets...')

        return self._run_az([
            'network', 'vnet', 'subnet', 'list',
            '--resource-group', self._selected_resource_group['name'],
            '--vnet-name', self._selected_virtual_network['name']
        ])

    def _create_subnet(self) -> dict:
        """
        Creates a new subnet.

        :return dict: the created subnet

        """
        name = ''
        while not name:
            name = input(self.format('Subnet network name: '))
            name = name.strip()

        prefix = ''
        while not subnet_prefix_valid(prefix):
            prefix = input(self.format('Network prefix (i.e. 10.0.0.0/24): '))
            prefix = prefix.strip()

        print('Creating subnet...')

        try:
            subnet = self._run_az([
                'network', 'vnet', 'subnet', 'create',
                '--name', name,
                '--address-prefix', prefix,
                '--vnet-name', self._selected_virtual_network['name'],
                '--network-security-group',
                self._selected_network_security_group['name'],
                '--resource-group', self._selected_resource_group['name']
            ])
            self._az_subnets.append(subnet)

        except APIError as e:
            print(self.format_error(str(e)))
            return self._create_subnet()

        return subnet

    def _get_storage_accounts(self) -> List[dict]:
        """
        Gets a list of storage accounts in resource group.

        :return List[dict]: a list of subnets

        """
        print('Getting storage accounts...')

        return self._run_az([
            'storage', 'account', 'list',
            '--resource-group', self._selected_resource_group['name']
        ])

    def _create_storage_account(self) -> dict:
        """
        Creates a new storage account.

        :return dict: the created storage account

        """
        name = ''
        while not storage_name_valid(name):
            name = input(
                self.format(
                    'Storage account name (3-24 characters, '
                    'lower-case letters and numbers only): '
                )
            )
            name = name.strip()

        print('Creating storage account...')

        try:
            storage_account = self._run_az([
                'storage', 'account', 'create',
                '--name', name,
                '--location', self._selected_resource_group['location'],
                '--resource-group', self._selected_resource_group['name'],
                '--sku', 'Premium_LRS',
                '--kind', 'Storage'
            ])
            self._az_storage_accounts.append(storage_account)

        except APIError as e:
            print(self.format_error(str(e)))
            return self._create_storage_account()

        return storage_account

    def _get_vm_sizes(self) -> List[dict]:
        """
        Gets a list of vm sizes.

        :return List[dict]: a list of vm sizes

        """
        print('Getting virtual machine sizes...')

        return self._run_az([
            'vm', 'list-sizes',
            '--location', self._selected_resource_group['location']
        ])

    def _select_image(self) -> dict:
        print('----------')

        urn: str = ''
        image: dict = None

        while not urn:
            urn = input(self.format('Enter the VM image URN: ')).strip()

            #
            # Attempt to get the image
            #
            try:
                image: dict = self._get_image(urn)
            except Exception:
                pass

            #
            # If there is no image, then the URN is invalid
            #
            if not image:
                print(self.format_error('That URN is not valid.'))
                urn = ''

        #
        # Store the URN on the image data for future reference
        #
        image['urn'] = urn

        return image

    def _get_image(self, urn) -> dict:
        print('Getting the image details...')

        return self._run_az([
            'vm', 'image', 'show',
            '--urn', urn
        ])

    def _run(self):
        """
        Runs the wizard.

        """
        #
        # Get the account information
        #
        self._az_account: dict = self._get_account()

        #
        # Select the application
        #
        self._az_applications = self._get_applications()
        self._selected_application = self._select_object('application',
                                                         'displayName')
        password = self._selected_application.get('password', None)
        if not password:
            while not password:
                password = input(
                    self.format('Enter the application API password: ')
                )
            self._selected_application['password'] = password

        #
        # Select the resource group
        #
        self._az_resource_groups = self._get_resource_groups()
        self._selected_resource_group = self._select_object('resource group',
                                                            'name')

        #
        # Check resource group permissions
        #
        self._az_role_assignments = self._get_role_assignments()
        self._check_role_assignments()

        #
        # Select the virtual network
        #
        self._az_virtual_networks = self._get_virtual_networks()
        self._selected_virtual_network = self._select_object(
            'virtual network', 'name')

        #
        # Select the network security group
        #
        self._az_network_security_groups = self._get_network_security_groups()
        self._selected_network_security_group = self._select_object(
            'network security group', 'name')

        #
        # Select the subnet
        #
        self._az_subnets = self._get_subnets()
        self._selected_subnet = self._select_object('subnet', 'name')

        #
        # Select the storage account
        #
        self._az_storage_accounts = self._get_storage_accounts()
        self._selected_storage_account = self._select_object(
            'storage account', 'name')

        #
        # Select VM size
        #
        self._az_vm_sizes = self._get_vm_sizes()
        self._selected_vm_size = self._select_object('vm_size', 'name',
                                                     create=False)

        #
        # Select image
        #
        self._selected_image = self._select_image()

        self._run_completed = True

        config: Dict[str, str] = self.get_config()
        self._write_config_to_file(config, 'default')
        self._write_config_to_db(config, 'default')

    def _select_object(self, name: str, name_attr: str,
                       create: bool = True) -> dict:
        """
        Selects and returns an object instance.

        :return dict: the selected object data

        """
        options: List[str] = []
        if create:
            options.append('c')

        print(self.format_white('----------'))
        print(self.format('The following is a list of {}:\n', name + 's'))

        obj_list_name: str = '_az_{}s'.format(name.replace(' ', '_'))
        obj_list = getattr(self, obj_list_name)

        for i in range(len(obj_list)):
            obj = obj_list[i]
            print(self.format_white('[{}] {}', i, obj[name_attr]))
            options.append(str(i))

        if len(obj_list):
            print('')

        if create:
            print(self.format_white('[c] Create a new {}\n', name))

        selected = ''
        while selected not in options:
            selected = input(self.format('Select {}: ', name))
            selected = str(selected).strip().lower()

        if create and selected == 'c':
            create_method = getattr(
                self,
                '_create_{}'.format(name.replace(' ', '_'))
            )
            obj = create_method()
        else:
            obj = obj_list[int(selected)]

        return obj

    def get_config(self) -> Dict[str, str]:
        if not self._run_completed:
            self._run()

        try:
            config = {
                'subscription_id': self._az_account['id'],
                'client_id': self._selected_application['appId'],
                'tenant_id': self._az_account['tenantId'],
                'secret': self._selected_application['password'],
                'resource_group': self._selected_resource_group['name'],
                'storage_account': self._selected_storage_account['name'],
                'location': self._selected_resource_group['location'],
                'size': self._selected_vm_size['name'],
                'default_login': 'ubuntu',
                'security_group':
                    self._selected_network_security_group['name'],
                'virtual_network_name':
                    self._selected_virtual_network['name'],
                'subnet_name': self._selected_subnet['name'],
                'image_urn': self._selected_image['urn'],
                'user_data_script_template': 'ubuntu_bootstrap.py.tmpl'
            }
        except KeyError:
            print(self._selected_application)
            print(self._selected_resource_group)
            print(self._selected_virtual_network)
            print(self._selected_network_security_group)
            print(self._selected_subnet)
            print(self._selected_storage_account)
            print(self._selected_vm_size)
            print(self._selected_image)
            raise

        return config


def url_valid(url: str) -> bool:
    """
    Determines whether or not a URL is in a valid format.

    :param str url: the URL to validate

    :return bool: True if valid, False otherwise

    """
    result = urlparse(url)
    if all([result.scheme, result.netloc]):
        return True
    return False


def subnet_prefix_valid(subnet_prefix: str) -> bool:
    """
    Determines whether or not a subnet prefix is in the following format:

        x.x.x.x/xx

    :param str subnet_prefix: the subnet prefix to validate

    :return: True if valid, falise otherwise

    """
    try:
        ipaddress.ip_network(subnet_prefix)
        return True
    except ValueError:
        pass
    return False


def storage_name_valid(name: str) -> bool:
    """
    Determines whether or not a storage account name is valid. Valid names
    must be between 3 and 24 characters in length, and use numbers and
    lower-case letters only.

    :param str name: the storage account name

    :return bool: True if valid, False otherwise

    """
    if re.match('[a-z0-9]{3,24}$', name):
        return True
    return False


def main():
    setup = ResourceAdapterSetup()
    setup.run()
