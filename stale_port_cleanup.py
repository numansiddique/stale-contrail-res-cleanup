import os
import sys

from neutronclient.v2_0.client import Client as NeutronClient


class StalePortCleanup():
    def __init__(self):
        kwargs = {}
        kwargs['username'] = os.environ.get('OS_USERNAME')
        kwargs['tenant_name'] = os.environ.get('OS_TENANT_NAME')
        kwargs['auth_url'] = os.environ.get('OS_AUTH_URL')
        # kwargs['endpoint_url'] = os.environ.get('OS_AUTH_URL')
        kwargs['auth_strategy'] = 'keystone'
        kwargs['password'] = os.environ.get('OS_PASSWORD')
        self.client = NeutronClient(**kwargs)
        self.subnets = []
        self.stale_ports = []
        self.stale_networks = {}
        self.all_ports = []

    def get_stale_ports(self):
        self.all_ports = self.client.list_ports()['ports']
        for port in self.all_ports or []:
            try:
                if not port['fixed_ips'] or not port['fixed_ips'][0]['subnet_id']:
                    self.stale_ports.append(port)
                    if port['network_id'] not in self.stale_networks:
                        self.stale_networks[port['network_id']] = {
                            'network_id': port['network_id'],
                            'tenant_id': port['tenant_id']}
            except Exception as e:
                print("Exception occured for port : " + str(port['id']) + "\n")

    def _display_stale_port_info(self, port):
        print('Port Id = ' + str(port['id']) + '\n')
        print('This port belongs to tenant : ' + str(port['tenant_id']) + '\n')
        print('This port belongs to network : ' + str(port['network_id'] + '\n'))
        if port['fixed_ips']:
            print("This port has IP address : " + str(port['fixed_ips'][0]['ip_address']) + "\n")
        if port['device_id']:
            print("This port has device id set to : " + str(port['device_id']) + "\n")
        if port['device_owner']:
            print("This port has device owner set to : " + str(port['device_owner']) + "\n")

    def display_stale_resources(self):
        print('Total stale ports found : ' + str(len(self.stale_ports)))
        if len(self.stale_ports):
            print('Below are the stale ports which will be deleted : Please review')
            for port in self.stale_ports:
                print('**************\n')
                self._display_stale_port_info(port)
                print('**************\n\n')
        print('\n\n##################################\n\n')

        print('Total stale networks found : ' + str(len(self.stale_networks)))

        if len(self.stale_networks):
            print('Below are the stale networks')
            for net_info in self.stale_networks.itervalues():
                print('**************\n')
                print('Network Id : ' + net_info['network_id'] + '\n')
                print("This network belongs to tenant : " + net_info['tenant_id'] + "\n")
                print('**************\n')

    def delete_stale_resources(self):
        print("Deleting the stale resources")
        for port in self.stale_ports:
            print("Deleting port : " + str(port['id']) + "\n")
            try:
                self.client.delete_port(port['id'])
            except Exception as e:
                print("Exception occured in deleting port : " + str(port['id']) +"\n")
                print("Exception e = " + str(e) + "\n")



stale_oc_res = StalePortCleanup()
print("This script lists the stale ports and stale networks whose subnet is deleted \n")
stale_oc_res.get_stale_ports()
stale_oc_res.display_stale_resources()

choice = raw_input("Press y to delete these resources : n to exit  :")

if choice != 'y':
    print("Exiting the script \n")
    sys.exit(0)


# stale_oc_res.delete_stale_resources()
