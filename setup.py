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

from setuptools import find_packages, setup


VERSION = '7.0.3'


if os.getenv('RELEASE'):
    requirements_file = 'requirements.txt'
else:
    requirements_file = 'requirements-dev.txt'


print("Using requirements file [{}]".format(requirements_file))


with open(requirements_file) as fp:
    requirements = [buf.rstrip() for buf in fp.readlines()]


setup(
    name='tortuga-azure-adapter',
    version=VERSION,
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
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'setup-azure=tortuga.resourceAdapter.azureadapter.scripts.setup_azure:main'
        ]
    }
)
