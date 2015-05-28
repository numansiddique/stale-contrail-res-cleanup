# Copyright (C) 2015 Cloudwatt
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
import argparse
import os
import sys

import ConfigParser
import netaddr

from cfgm_common import exceptions as vnc_exc
from neutronclient.v2_0.client import Client as NeutronClient
from vnc_api import vnc_api


class CleanStaleResource(object):

    def __init__(self, **kwargs):
        username = kwargs.get('username')
        if not username:
            username = os.environ.get('OS_USERNAME')

        if username is None:
            print("Please specify the username or source the localrc with the "
                  " login credentials")
            sys.exit(0)

        password = kwargs.get('password')
        if not password:
            password = os.environ.get('OS_PASSWORD')

        tenant_name = kwargs.get('tenant')
        if not tenant_name:
            tenant_name = os.environ.get('OS_TENANT_NAME')

        auth_host = kwargs.get('auth_host')
        if not auth_host:
            auth_host = 'identity.usr.lab0.aub.cloudwatt.net'

        auth_port = kwargs.get('auth_port')
        if not auth_port:
            auth_port = '5000'

        auth_url = kwargs.get('auth_url')
        # auth_url = os.environ.get('OS_AUTH_URL')
        auth_url = '/v2.0/tokens'
        api_server_ip = kwargs.get('api_server_ip')
        if not api_server_ip:
            api_server_ip = '127.0.0.1'
        api_server_port = kwargs.get('api_server_port')
        if not api_server_port:
            api_server_port = '8082'
        # get the contrail admin user and password
        try:
            self._vnc_lib = vnc_api.VncApi(username=username,
                                           password=password,
                                           tenant_name=tenant_name,
                                           api_server_host=api_server_ip,
                                           api_server_port=api_server_port,
                                           auth_host=auth_host,
                                           auth_port=auth_port,
                                           auth_url=auth_url)
        except Exception as e:
            print 'Exception occured while connecting to VncApi .', e
            return

        self.stale_port_info = []
        self.subnets_info = []
        self.stale_subnets_info = []

    def _get_contrail_admin_pwd(self, conf_file):
        admin_user = ''
        admin_pwd = ''
        config = ConfigParser.SafeConfigParser({'admin_token': None})
        config.read(conf_file)
        if 'KEYSTON' in config.sections():
            for (k, v) in config.items('KEYSTONE'):
                if k == 'admin_user':
                    admin_user = v
                    continue
                if k == 'admin_password':
                    admin_pwd = v
                    continue
        return (admin_user, admin_pwd)

    def _get_vmi_net_id(self, vmi_obj):
        net_refs = vmi_obj.get_virtual_network_refs()
        if net_refs:
            return net_refs[0]['uuid']

    def _ip_address_to_subnet_id(self, ip_addr, vn_obj):
        vnc_subnet_id_set = True
        subnet_id = None
        ipam_refs = vn_obj.get_network_ipam_refs()
        for ipam_ref in ipam_refs or []:
            subnet_vncs = ipam_ref['attr'].get_ipam_subnets()
            for subnet_vnc in subnet_vncs:
                cidr = '%s/%s' % (subnet_vnc.subnet.get_ip_prefix(),
                                  subnet_vnc.subnet.get_ip_prefix_len())
                if netaddr.IPAddress(ip_addr) in netaddr.IPSet([cidr]):
                    subnet_id = subnet_vnc.subnet_uuid
                    if not subnet_id:
                        vnc_subnet_id_set = False
                        subnet_key = self._subnet_vnc_get_key(subnet_vnc,
                                                              vn_obj.uuid)
                        try:
                            subnet_id = self._vnc_lib.kv_retrieve(subnet_key)
                        except vnc_exc.NoIdError:
                            subnet_id = None

        return (vnc_subnet_id_set, subnet_id)

    @staticmethod
    def _subnet_vnc_get_key(subnet_vnc, net_id):
        pfx = subnet_vnc.subnet.get_ip_prefix()
        pfx_len = subnet_vnc.subnet.get_ip_prefix_len()

        network = netaddr.IPNetwork('%s/%s' % (pfx, pfx_len))
        return '%s %s/%s' % (net_id, str(network.ip), pfx_len)

    def _get_vmi_ip_dict(self, vmi_obj, vn_obj):
        ip_dict_list = []
        ip_back_refs = getattr(vmi_obj, 'instance_ip_back_refs', None)
        for ip_back_ref in ip_back_refs or []:
            iip_uuid = ip_back_ref['uuid']
            try:
                ip_obj = self._vnc_lib.instance_ip_read(id=iip_uuid)
            except vnc_exc.NoIdError:
                continue

            ip_addr = ip_obj.get_instance_ip_address()
            vnc_subnet_id_set, subnet_id = (
                self._ip_address_to_subnet_id(ip_addr, vn_obj))
            ip_q_dict = {'ip_address': ip_addr,
                         'subnet_id': subnet_id,
                         'vnc_subnet_id_set': vnc_subnet_id_set}

            ip_dict_list.append(ip_q_dict)

        return ip_dict_list

    def _check_if_stale_vmi(self, vmi_obj):
        net_id = self._get_vmi_net_id(vmi_obj)
        try:
            vn_obj = self._vnc_lib.virtual_network_read(id=net_id)
        except:
            self.stale_port_info.append({'is_stale': True,
                                         'vn_obj': None,
                                         'vmi_obj': vmi_obj,
                                         'id': vmi_obj.uuid})
            return True

        vmi_ip_dict_list = self._get_vmi_ip_dict(vmi_obj, vn_obj)
        for vmi_ip_dict in vmi_ip_dict_list:
            vnc_subnet_id_set = vmi_ip_dict.get('vnc_subnet_id_set')
            if not vnc_subnet_id_set:
                self.stale_port_info.append(
                    {'id': vmi_obj.uuid, 'is_stale': True,
                     'network_id': vn_obj.uuid, 'vn_obj': vn_obj,
                     'vmi_obj': vmi_obj,
                     'tenant_id': vn_obj.parent_uuid.replace('-', ''),
                     'vmi_ip_dict': vmi_ip_dict})
                return True
        return False

    def _check_stale_vmi_ports(self):
        back_ref_fields = ['logical_router_back_refs', 'instance_ip_back_refs',
                           'floating_ip_back_refs']
        vmi_objs = self._vnc_lib.virtual_machine_interfaces_list(
            detail=True, fields=back_ref_fields)
        for vmi_obj in vmi_objs or []:
            self._check_if_stale_vmi(vmi_obj)

    def _get_all_vns(self):
        vn_objs = self._vnc_lib.virtual_networks_list(detail=True)
        return vn_objs

    def _add_subnet_info(self, subnet_vnc, vn_obj, ipam_fq_name):
        cidr = '%s/%s' % (subnet_vnc.subnet.get_ip_prefix(),
                          subnet_vnc.subnet.get_ip_prefix_len())
        subnet_id = subnet_vnc.subnet_uuid
        vnc_subnet_id_set = True
        if not subnet_id:
            vnc_subnet_id_set = False
            subnet_key = self._subnet_vnc_get_key(subnet_vnc, vn_obj.uuid)
            try:
                subnet_id = self._vnc_lib.kv_retrieve(subnet_key)
            except vnc_exc.NoIdError:
                subnet_id = None
        subnet_info = {'subnet_vnc': subnet_vnc,
                       'vnc_subnet_id_set': vnc_subnet_id_set,
                       'subnet_id': subnet_id,
                       'cidr': cidr,
                       'network_id': vn_obj.uuid,
                       'tenant_id': vn_obj.parent_uuid.replace('-', '')}
        self.subnets_info.append(subnet_info)
        if not vnc_subnet_id_set:
            self.stale_subnets_info.append(subnet_info)

    def _check_stale_subnets(self):
        vn_objs = self._get_all_vns()
        for vn_obj in vn_objs or []:
            ipam_refs = vn_obj.get_network_ipam_refs()
            for ipam_ref in ipam_refs or []:
                subnet_vncs = ipam_ref['attr'].get_ipam_subnets()
                for subnet_vnc in subnet_vncs:
                    self._add_subnet_info(subnet_vnc, vn_obj, ipam_ref['to'])

    def check_stale_resources(self):
        if not self._vnc_lib:
            print('Not connected to the VncApi. Check the config-api '
                  'configuration file or run this utility in the config node')
            sys.exit()

        self._check_stale_vmi_ports()
        self._check_stale_subnets()

    def display_stale_resources(self):
        print('Number of Stale Ports : ' + str(len(self.stale_port_info)) + '\n\n')
        if self.stale_port_info:
            print 'Stale Ports Info : '
        for stale_port in self.stale_port_info:
            for k, v in stale_port.items():
                if k == 'vn_obj' or k == 'vmi_obj':
                    continue
                print '\t ' + str(k) + ' :' + str(v) + '\n'
            print '*********************************************************\n'

        print('\n\n##################################################\n')
        print('Number of Stale Subnets : ' + str(len(self.stale_subnets_info)) + '\n\n')
        if len(self.stale_subnets_info):
            print 'Stale Subnet Info : '
            for stale_subnet in self.stale_subnets_info:
                for k, v in stale_subnet.items():
                    if k == 'subnet_vnc':
                        continue
                    print '\t ' + str(k) + ' :' + str(v) + '\n'
                print '******************************************************\n'

        print '\n\n'

parser = argparse.ArgumentParser(description='Check for stale resources')

parser.add_argument('--auth_url', metavar='URL', type=str,
                    help='Keystone URL')
parser.add_argument('--auth_host', metavar='hostname', type=str,
                    help='Keystone auth host')

parser.add_argument('--auth_port', metavar='port', type=str,
                    help='Keystone port')

parser.add_argument('--username', metavar='username', type=str,
                    help='username to use for authentication')

parser.add_argument('--password', metavar='password', type=str,
                    help='password to use for authentication')

parser.add_argument('--tenant', metavar='tenant', type=str,
                    help='tenant name to use for authentication')

parser.add_argument('--api_server_ip', metavar='api_server_ip', type=str,
                    help='API server ip address')

parser.add_argument('--api_server_port', metavar='api_server_port', type=str,
                    help='API server port')

args = parser.parse_args()

stale_res_handler = CleanStaleResource(auth_url=args.auth_url,
                                       auth_host=args.auth_host,
                                       auth_port=args.auth_port,
                                       username=args.username,
                                       password=args.password,
                                       tenant=args.tenant,
                                       api_server_ip=args.api_server_ip,
                                       api_server_port=args.api_server_port)


stale_res_handler.check_stale_resources()
stale_res_handler.display_stale_resources()
