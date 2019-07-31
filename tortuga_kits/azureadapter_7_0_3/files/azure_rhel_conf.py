#!/usr/bin/env python

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
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib2
import itertools
import socket


### SETTINGS

def get_instance_data(path):
    url = 'http://169.254.169.254/metadata/instance' + path + "?api-version=2019-04-30&format=text"

    req = urllib2.Request(url)
    req.add_header('Metadata', 'true')

    for nCount in range(5):
        try:
            response = urllib2.urlopen(req)
            break
        except urllib2.URLError as ex:
            pass
        except urllib2.HTTPError as ex:
            if ex.code == 404:
                raise

            time.sleep(2 ** (nCount + 1))
    else:
        raise Exception('Unable to communicate with metadata webservice')

    if response.code != 200:
        raise Exception('Unable to read %s' % path)
    return response.read()

def addNode():
    tryCommand("mkdir -p /etc/pki/ca-trust/source/anchors/")
    tryCommand("curl http://%s:8008/ca.pem > /etc/pki/ca-trust/source/anchors/tortuga-ca.pem" % installerIpAddress)
    tryCommand("update-ca-trust")
    instance_name = get_instance_data('/compute/name')
    host_name = socket.getfqdn()+ "." + dns_domain
    private_ip = get_instance_data('/network/interface/0/ipv4/ipAddress/0/privateIpAddress')
    try:
        scale_set_name = get_instance_data('/compute/vmScaleSetName')
        instance_id = int(instance_name.rsplit('_',1)[1])
    except:
        instance_id = instance_name
        scale_set_name = ""
    data = {
            'node_details': {
                'name': host_name,
                'metadata': {
                    'instance_id': instance_id,
                    'private_ip': private_ip,
                    'scale_set_name': scale_set_name,
                }
            }
           }
    print(data)
    url = 'https://%s:%s/v1/node-token/%s' % (installerHostName, port, insertnode_request)
    print(url)
    req = urllib2.Request(url)

    req.add_header('Content-Type', 'application/json')

    for nCount in range(5):
        try:
            response = urllib2.urlopen(req, json.dumps(data))
            break
        except urllib2.URLError as ex:
            print(ex)
            pass
        except urllib2.HTTPError as ex:
            if ex.code == 401:
                raise Exception(
                    'Invalid Tortuga webservice credentials')
            elif ex.code == 404:
                # Unrecoverable
                raise Exception(
                    'URI not found; invalid Tortuga webservice'
                    ' configuration')

            time.sleep(2 ** (nCount + 1))
    else:
        raise Exception('Unable to communicate with Tortuga webservice')

    d = json.load(response)

    if response.code != 200:
        if 'error' in d:
            errmsg = 'Tortuga webservice error: msg=[%s]' % (
                error['message'])
        else:
            errmsg = 'Tortuga webservice internal error'

        raise Exception(errmsg)
    print(d)

def tryCommand(command, good_return_values=(0,), retry_limit=0,
               time_limit=0, max_sleep_time=15000, sleep_interval=2000):
    total_sleep_time = 0
    returned = -1
    for retries in itertools.count(0):
        returned = subprocess.Popen(command, shell=True).wait()
        if returned in good_return_values or \
                retries >= retry_limit or total_sleep_time >= time_limit:
            return returned

        seed = min(max_sleep_time, sleep_interval * 2 ** retries)
        sleep_for = (seed / 2 + random.randint(0, seed / 2)) / 1000.0
        total_sleep_time += sleep_for

        time.sleep(sleep_for)
    return returned

def _installPackage(pkgList, yumopts=None, retries=10):
    cmd = 'yum'

    if yumopts:
        cmd += ' ' + yumopts

    cmd += ' -y install %s' % pkgList

    retval = tryCommand(cmd, retry_limit=retries)
    if retval != 0:
        raise Exception('Error installing package [%s]' % (pkgList))

def _isPackageInstalled(pkgName):
    return tryCommand('rpm -q --quiet %s' % pkgName) == 0


def install_puppet(vers):
    pkgname = 'puppet5-release'

    url = 'http://yum.puppetlabs.com/puppet5/%s-el-%s.noarch.rpm' % (pkgname, vers)

    bRepoInstalled = _isPackageInstalled(pkgname)

    if not bRepoInstalled:
        retval = tryCommand('rpm -ivh %s' % (url), retry_limit=5)
        if retval != 0:
            sys.stderr.write(
                'Error: unable to install package \"{0}\"\n'.format(pkgname))

            sys.exit(1)

    # Attempt to install puppet
    if not _isPackageInstalled('puppet-agent'):
        _installPackage('puppet-agent')

def update_resolv_conf():
    found_nameserver = False

    nss = dns_nameservers \
        if override_dns_domain else [installerIpAddress]

    fn= '/etc/resolv.conf'

    with open(fn) as fpIn:
        with open(fn + '.tortuga', 'w') as fpOut:
            fpOut.write('# Rewritten by Tortuga\n')

            for inbuf in fpIn.readlines():
                if inbuf.startswith('search '):
                    if not inbuf.startswith('search {0}'.format(dns_search)):
                        _, args = inbuf.rstrip().split('search', 1)

                        fpOut.write('search {0} {1}\n'.format(dns_search, args))
                elif inbuf.startswith('nameserver'):
                    if not found_nameserver:
                        fpOut.write('\n'.join(
                            ['nameserver {0}\n'.format(ns) for ns in nss]))
                        found_nameserver = True

                    fpOut.write(inbuf)

    shutil.move(fn, fn + '.orig')
    shutil.copyfile(fn + '.tortuga', fn)

def bootstrap_puppet():
    tryCommand("touch /tmp/puppet_bootstrap.log")
    cmd = ('/opt/puppetlabs/bin/puppet agent'
           ' --logdest /tmp/puppet_bootstrap.log'
           ' --no-daemonize'
           ' --onetime --server %s --waitforcert 120' % (installerHostName))

    tryCommand(cmd)

def register_compute():
    tryCommand('echo "%s" >> /.tortuga_execd' %(installerHostName))

def main():
    register_compute()
    vals = platform.dist()

    distro_maj_vers = vals[1].split('.')[0]

    update_resolv_conf()

    if insertnode_request is not None:
        addNode()

    install_puppet(distro_maj_vers)

    bootstrap_puppet()


if __name__ == '__main__':
    main()
