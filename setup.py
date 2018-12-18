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
import subprocess

from setuptools import find_packages, setup

version = '7.0.2'


def get_git_revision():
    cmd = 'git rev-parse --short HEAD'

    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    result, _ = p.communicate()
    p.wait()

    return result.decode().rstrip()


git_revision = get_git_revision()

module_version = f'{version}+rev{git_revision}'

if os.getenv('CI_PIPELINE_ID'):
    module_version += '.{}'.format(os.getenv('CI_PIPELINE_ID'))


setup(
    name='tortuga-azure-adapter',
    version=module_version,
    url='http://univa.com',
    author='Univa Corporation',
    author_email='engineering@univa.com',
    license='Apache 2.0',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    namespace_packages=[
        'tortuga',
        'tortuga.resourceAdapter'
    ],
    zip_safe=False,
    install_requires=[
        #
        # We need to pin urllib3 here otherwise requests
        # (required by azure-cli) breaks and throws warning messages
        #
        'urllib3==1.22',
        'azure-cli',
        'colorama',
        'gevent',
        'msrestazure<0.5.0',
        'Jinja2',
    ],
    entry_points = {
        'console_scripts': [
            'setup-azure=tortuga.resourceAdapter.azureadapter.scripts.setup_azure:main'
        ]
    }
)
