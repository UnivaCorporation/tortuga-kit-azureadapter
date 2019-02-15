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

import sys
import subprocess
import platform
import time
import shutil

### SETTINGS


def runCommand(cmd, retries=1):
    for nRetry in range(retries):
        p = subprocess.Popen(cmd, shell=True)

        retval = p.wait()
        if retval == 0:
            break

        time.sleep(5 + 2 ** (nRetry * 0.75))
    else:
        return -1

    return retval


def _installPackage(pkgList, yumopts=None, retries=10):
    cmd = 'yum'

    if yumopts:
        cmd += ' ' + yumopts

    cmd += ' -y install %s' % (pkgList)

    retval = runCommand(cmd, retries)
    if retval != 0:
        raise Exception('Error installing package [%s]' % (pkgList))


def installEPEL(vers):
    epelbaseurl = ('http://dl.fedoraproject.org/pub/epel'
                   '/epel-release-latest-%s.noarch.rpm' % (vers))

    runCommand('rpm -ivh %s' % (epelbaseurl))


def _isPackageInstalled(pkgName):
    return (runCommand('rpm -q --quiet %s' % (pkgName)) == 0)


def installPuppet(vers):
    pkgname = 'puppet5-release'

    url = 'http://yum.puppetlabs.com/puppet5/%s-el-%s.noarch.rpm' % (pkgname, vers)

    bRepoInstalled = _isPackageInstalled(pkgname)

    if not bRepoInstalled:
        retval = runCommand('rpm -ivh %s' % (url), 5)
        if retval != 0:
            sys.stderr.write(
                'Error: unable to install package \"{0}\"\n'.format(pkgname))

            sys.exit(1)

    # Attempt to install puppet
    if not _isPackageInstalled('puppet-agent'):
        _installPackage('puppet-agent')


def bootstrapPuppet():
    cmd = ('/opt/puppetlabs/bin/puppet agent'
           ' --logdest /tmp/puppet_bootstrap.log'
           ' --onetime --server %s --waitforcert 120' % (installerHostName))

    runCommand(cmd)


def get_default_dns_domain():
    results = installerHostName.rstrip().split('.', 1)

    return results[1] if len(results) == 2 else None


def update_resolv_conf():
    domain = dns_search if dns_search else get_default_dns_domain()

    with open('/etc/resolv.conf', 'w') as fp:
        if dns_nameservers:
            for ns in dns_nameservers:
                fp.write('nameserver %s\n' % (ns))
        else:
            fp.write('nameserver %s\n' % (installerIpAddress))

        if domain:
            fp.write('search %s\n' % (domain))


def update_network_configuration():
    nameserver_found = False
    domain_found = False

    fn = '/etc/sysconfig/network-scripts/ifcfg-eth0'

    with open(fn) as fp:
        with open(fn + '.NEW', 'w') as fpOut:
            for buf in fp.readlines():
                if buf.startswith('PEERDNS='):
                    fpOut.write('PEERDNS=no\n')
                    continue
                elif buf.startswith('DNS1='):
                    nameserver_found = True
                    fpOut.write('DNS1={0}\n'.format(installerIpAddress))
                    continue
                elif buf.startswith('DOMAIN=') and override_dns_domain:
                    domain_found = True
                    fpOut.write('DOMAIN={0}\n'.format(dns_search))
                    continue

                fpOut.write(buf)

            if not nameserver_found:
                fpOut.write('DNS1={0}\n'.format(installerIpAddress))

            if not domain_found and override_dns_domain:
                fpOut.write('DOMAIN={0}\n'.format(dns_search))

    shutil.move(fn, fn + '.orig')
    shutil.move(fn + '.NEW', fn)


def main():
    runCommand('setenforce permissive')

    update_resolv_conf()

    update_network_configuration()

    vals = platform.dist()

    vers = vals[1].split('.')[0]

    # Install EPEL repository, if necessary
    if not _isPackageInstalled('epel-release'):
        installEPEL(vers)

    with open('/etc/hosts', 'a+') as fp:
        fp.write('%s\t%s\n' % (installerIpAddress, installerHostName))

    installPuppet(vers)

    bootstrapPuppet()


if __name__ == '__main__':
    main()
