
import os
import sys
import time
import uuid
from vnc_api import vnc_api
try:
    import novaclient.v1_1.client
    config_nova = True
except:
    config_nova = False


class ConfigObject(object):
    def __init__(self, client, parent_fq_name, obj_read_func, obj_list_func):
        self.vnc = client.vnc
        self.tenant = client.tenant
        self.parent_fq_name = parent_fq_name
        self.obj_read_func = obj_read_func
        self.obj_list_func = obj_list_func

    def fq_name_get(self, name, str = False):
        fq_name = list(self.parent_fq_name)
        for item in name.split(':'):
            fq_name.append(item)
        if str:
            fq_name_str = 'default-domain'
            for item in fq_name[1:]:
                fq_name_str += ':%s' %(item)
            return fq_name_str
        else:
            return fq_name

    def obj_get(self, name, msg = False):
        fq_name = self.fq_name_get(name)
        try:
            obj = self.obj_read_func(fq_name = fq_name)
            return obj
        except:
            if msg:
                print 'ERROR: Object %s is not found!' %(fq_name)

    def show_json(self, obj):
        import json
        print json.dumps(obj, default = self.vnc._obj_serializer_all,
                indent=4, separators=(',', ': '))

    def show_dict(self, obj):
        import pprint
        pp = pprint.PrettyPrinter(indent = 1, width = 80)
        pp.pprint(self.vnc.obj_to_dict(obj))

    def show_list(self):
        dict = self.obj_list_func()
        for item in dict[dict.keys()[0]]:
            p_len = len(self.parent_fq_name)
            if (item['fq_name'][:p_len] == self.parent_fq_name):
                name_str = item['fq_name'][p_len]
                if (len(item['fq_name']) > (p_len + 1)):
                    for name in item['fq_name'][(p_len + 1):]:
                        name_str += ':%s' %(name)
                print name_str

    def show(self, args):
        if args.name:
            obj = self.obj_get(args.name, msg = True)
            if not obj:
                return
            if (args.format == 'json'):
                self.show_json(obj)
            elif (args.format == 'dict'):
                self.show_dict(obj)
            else:
                self.show_obj(obj)      
        else:
            self.show_list()


class ConfigTenant(ConfigObject):
    def __init__(self, client):
        super(ConfigTenant, self).__init__(client,
                ['default-domain'],
                client.vnc.project_read,
                client.vnc.projects_list)

    def show_obj(self, obj):
        print '## Tenant (Project)'
        print 'Name: %s' %(obj.get_fq_name())
        print 'UUID: %s' %(obj.uuid)

    def add(self, name):
        domain = self.vnc.domain_read(fq_name = ['default-domain'])
        obj = vnc_api.Project(name = name, parent_obj = domain)
        try:
            self.vnc.project_create(obj)
        except Exception as e:
            print 'ERROR: %s' %(str(e))

    def delete(self, name):
        obj = self.obj_get(name, msg = True)
        if not obj:
            return
        try:
            self.vnc.project_delete(id = obj.uuid)
        except Exception as e:
            print 'ERROR: %s' %(str(e))


class ConfigIpam(ConfigObject):
    def __init__(self, client):
        super(ConfigIpam, self).__init__(client,
                ['default-domain', client.tenant.name],
                client.vnc.network_ipam_read,
                client.vnc.network_ipams_list)

    def show_dns(self, mgmt):
        print '    DNS Type: %s' %(mgmt.ipam_dns_method)
        if (mgmt.ipam_dns_method == 'virtual-dns-server'):
            print '        Virtual DNS Server: %s' %(
                    mgmt.get_ipam_dns_server().virtual_dns_server_name)
        elif (mgmt.ipam_dns_method == 'tenant-dns-server'):
            list = mgmt.get_ipam_dns_server().get_tenant_dns_server_address(
                    ).get_ip_address()
            print '        Tenant DNS Server:'
            for item in list:
                print '            %s' %(item)

    def show_dhcp(self, mgmt):
        dhcp_opt = {'4':'NTP Server', '15':'Domain Name'}
        print '    DHCP Options:'
        dhcp = mgmt.get_dhcp_option_list()
        if not dhcp:
            return
        for item in dhcp.get_dhcp_option():
            print '        %s: %s' %(dhcp_opt[item.dhcp_option_name],
                    item.dhcp_option_value)

    def show_obj(self, obj):
        print '## Network IPAM'
        print 'Name: %s' %(obj.get_fq_name())
        print 'UUID: %s' %(obj.uuid)
        print 'Management:'
        mgmt = obj.get_network_ipam_mgmt()
        if not mgmt:
            return
        self.show_dns(mgmt)
        self.show_dhcp(mgmt)


    def add_dns(self, mgmt, dns_type, virtual_dns = None, tenant_dns = None):
        type = {'none':'none',
                'default':'default-dns-server',
                'virtual':'virtual-dns-server',
                'tenant':'tenant-dns-server'}
        if not dns_type:
            return
        mgmt.set_ipam_dns_method(type[dns_type])
        if virtual_dns:
            mgmt.set_ipam_dns_server(vnc_api.IpamDnsAddressType(
                    virtual_dns_server_name = virtual_dns))
        if tenant_dns:
            mgmt.set_ipam_dns_server(vnc_api.IpamDnsAddressType(
                    tenant_dns_server_address = vnc_api.IpAddressesType(
                    ip_address = tenant_dns)))

    def add_dhcp(self, mgmt, domain_name = None, ntp_server = None):
        if domain_name:
            list = mgmt.get_dhcp_option_list()
            if not list:
                list = vnc_api.DhcpOptionsListType()
                mgmt.set_dhcp_option_list(list)
            list.add_dhcp_option(vnc_api.DhcpOptionType(
                    dhcp_option_name = '15',
                    dhcp_option_value = domain_name))
        if ntp_server:
            list = mgmt.get_dhcp_option_list()
            if not list:
                list = vnc_api.DhcpOptionsListType()
                mgmt.set_dhcp_option_list()
            list.add_dhcp_option(vnc_api.DhcpOptionType(
                    dhcp_option_name = '4',
                    dhcp_option_value = ntp_server))

    def add(self, name, dns_type, virtual_dns = None, tenant_dns = None,
            domain_name = None, ntp_server = None):
        create = False
        obj = self.obj_get(name)
        if not obj:
            obj = vnc_api.NetworkIpam(name = name, parent_obj = self.tenant)
            create = True
        mgmt = obj.get_network_ipam_mgmt()
        if not mgmt:
            mgmt = vnc_api.IpamType()
            obj.set_network_ipam_mgmt(mgmt)
        self.add_dns(mgmt, dns_type, virtual_dns, tenant_dns)
        self.add_dhcp(mgmt, domain_name, ntp_server)
        if create:
            try:
                self.vnc.network_ipam_create(obj)
            except Exception as e:
                print 'ERROR: %s' %(str(e))
        else:
            self.vnc.network_ipam_update(obj)

    def delete(self, name, domain_name = None):
        update = False
        obj = self.obj_get(name, msg = True)
        if not obj:
            return
        if domain_name:
            mgmt = obj.get_network_ipam_mgmt()
            list = mgmt.get_dhcp_option_list()
            for item in list.get_dhcp_option():
                if (item.dhcp_option_name == '15') and \
                    (item.dhcp_option_value == domain_name):
                    list.delete_dhcp_option(item)
                    break
            update = True
        if update:
            self.vnc.network_ipam_update(obj)
        else:
            try:
                self.vnc.network_ipam_delete(id = obj.uuid)
            except Exception as e:
                print 'ERROR: %s' %(str(e))


class ConfigPolicy(ConfigObject):
    def __init__(self, client):
        super(ConfigPolicy, self).__init__(client,
                ['default-domain', client.tenant.name],
                client.vnc.network_policy_read,
                client.vnc.network_policys_list)

    def show_addr(self, addr_list):
        for item in addr_list:
            print '        Virtual Network: %s' %(item.virtual_network)

    def show_port(self, port_list):
        for item in port_list:
            print '        %d:%d' %(item.start_port, item.end_port)

    def show_action(self, rule):
        if rule.action_list.apply_service:
            for item in rule.action_list.apply_service:
                print '        %s' %(item)
        else:
            print '        %s' %(rule.action_list.simple_action)

    def show_rule(self, obj):
        entries = obj.get_network_policy_entries()
        if not entries:
            return
        count = 1
        for rule in entries.get_policy_rule():
            print 'Rule #%d' %(count)
            print '    Direction: %s' %(rule.direction)
            print '    Protocol: %s' %(rule.protocol)
            print '    Source Addresses:'
            self.show_addr(rule.src_addresses)
            print '    Source Ports:'
            self.show_port(rule.src_ports)
            print '    Destination Addresses:'
            self.show_addr(rule.dst_addresses)
            print '    Destination Ports:'
            self.show_port(rule.dst_ports)
            print '    Action:'
            self.show_action(rule)
            count += 1

    def show_obj(self, obj):
        print '## Policy'
        print 'Name: %s' %(obj.get_fq_name())
        print 'UUID: %s' %(obj.uuid)
        self.show_rule(obj)
        print '[BR] Virtual Network:'
        list = obj.get_virtual_network_back_refs()
        if list:
            for item in list:
                print '    %s' %(item['to'][2])

    def add_rule(self, arg_list):
        direction = None
        protocol = None
        src_net_list = []
        dst_net_list = []
        src_port_list = []
        dst_port_list = []
        action = None
        service_list = []
        for arg in arg_list:
            arg_name = arg.split('=')[0]
            arg_val = arg.split('=')[1]
            if (arg_name == 'direction'):
                direction = arg_val
            elif (arg_name == 'protocol'):
                protocol = arg_val
            elif (arg_name == 'src-net'):
                net = self.fq_name_get(arg_val, str = True)
                src_net_list.append(vnc_api.AddressType(virtual_network = net))
            elif (arg_name == 'dst-net'):
                net = self.fq_name_get(arg_val, str = True)
                dst_net_list.append(vnc_api.AddressType(virtual_network = net))
            elif (arg_name == 'src-port'):
                if (arg_val == 'any'):
                    src_port_list.append(vnc_api.PortType(
                            start_port = -1, end_port = -1))
                else:
                    s_e = arg_val.split(':')
                    src_port_list.append(vnc_api.PortType(
                            start_port = int(s_e[0]), end_port = int(s_e[1])))
            elif (arg_name == 'dst-port'):
                if (arg_val == 'any'):
                    src_port_list.append(vnc_api.PortType(
                            start_port = -1, end_port = -1))
                else:
                    s_e = arg_val.split(':')
                    src_port_list.append(vnc_api.PortType(
                            start_port = int(s_e[0]), end_port = int(s_e[1])))
            elif (arg_name == 'action'):
                action = arg_val
            elif (arg_name == 'service'):
                service_list.append(self.fq_name_get(arg_val, str = True))
 
        rule = vnc_api.PolicyRuleType()
        if not direction:
            direction = '<>'
        rule.set_direction(direction)
        if not protocol:
            protocol = 'any'
        rule.set_protocol(protocol)
        if not src_net_list:
            src_net_list.append(vnc_api.AddressType(virtual_network = 'any'))
        rule.set_src_addresses(src_net_list)
        if not dst_net_list:
            dst_net_list.append(vnc_api.AddressType(virtual_network = 'any'))
        rule.set_dst_addresses(dst_net_list)
        if not src_port_list:
            src_port_list.append(vnc_api.PortType(
                    start_port = -1, end_port = -1))
        rule.set_src_ports(src_port_list)
        if not dst_port_list:
            dst_port_list.append(vnc_api.PortType(
                    start_port = -1, end_port = -1))
        rule.set_dst_ports(dst_port_list)
        if not action:
            action_list = vnc_api.ActionListType(simple_action = 'pass')
        elif (action == 'service'):
            action_list = vnc_api.ActionListType(apply_service = service_list)
        else:
            action_list = vnc_api.ActionListType(simple_action = action)
        rule.set_action_list(action_list)
        return rule

    def add(self, name, rule_arg_list):
        rule_list = []
        if not rule_arg_list:
            rule = self.add_rule([])
            rule_list.append(rule)
        else:
            for rule_arg in rule_arg_list:
                rule = self.add_rule(rule_arg.split(','))
                rule_list.append(rule)

        obj = self.obj_get(name)
        if obj:
            rules = obj.get_network_policy_entries()
            if not rules:
                rules = vnc_api.PolicyEntriesType(policy_rule = rule_list)
            else:
                for item in rule_list:
                    rules.add_policy_rule(item)
            obj.set_network_policy_entries(rules)
            try:
                self.vnc.network_policy_update(obj)
            except Exception as e:
                print 'ERROR: %s' %(str(e))
        else:
            rules = vnc_api.PolicyEntriesType(policy_rule = rule_list)
            obj = vnc_api.NetworkPolicy(name = name,
                    parent_obj = self.tenant,
                    network_policy_entries = rules)
            try:
                self.vnc.network_policy_create(obj)
            except Exception as e:
                print 'ERROR: %s' %(str(e))

    def delete(self, name, rule_arg_list):
        obj = self.obj_get(name, msg = True)
        if not obj:
            return
        if rule_arg_list:
            rules = obj.get_network_policy_entries()
            if not rules:
                return
            for rule_arg in rule_arg_list:
                for arg in rule_arg.split(','):
                    arg_name = arg.split('=')[0]
                    arg_val = arg.split('=')[1]
                    if (arg_name == 'index'):
                        rule = rules.get_policy_rule()[int(arg_val) - 1]
                        rules.delete_policy_rule(rule)
            obj.set_network_policy_entries(rules)
            self.vnc.network_policy_update(obj)
        else:
            try:
                self.vnc.network_policy_delete(id = obj.uuid)
            except Exception as e:
                print 'ERROR: %s' %(str(e))


class ConfigSecurityGroup(ConfigObject):
    def __init__(self, client):
        super(ConfigSecurityGroup, self).__init__(client,
                ['default-domain', client.tenant.name],
                client.vnc.security_group_read,
                client.vnc.security_groups_list)

    def show_port(self, port_list):
        for item in port_list:
            print '        %d:%d' %(item.get_start_port(), item.get_end_port())

    def show_rule(self, obj):
        entries = obj.get_security_group_entries()
        if not entries:
            return
        count = 1
        for rule in entries.get_policy_rule():
            print 'Rule #%d' %(count)
            print '    Direction: %s' %(rule.get_direction())
            print '    Protocol: %s' %(rule.get_protocol())
            print '    Source Addresses:'
            self.show_addr(rule.get_src_addresses())
            print '    Source Ports:'
            self.show_port(rule.get_src_ports())
            print '    Destination Addresses:'
            self.show_addr(rule.get_dst_addresses())
            print '    Destination Ports:'
            self.show_port(rule.get_dst_ports())
            count += 1

    def show_obj(self, obj):
        print '## Security Group'
        print 'Name: %s' %(obj.get_fq_name())
        print 'UUID: %s' %(obj.uuid)
        self.show_rule(obj)

    def add(self, name, protocol = None, address = None, port = None,
            direction = None):
        rule = vnc_api.PolicyRuleType()
        rule.set_direction('>')
        if protocol:
            rule.set_protocol(protocol)
        else:
            rule.set_protocol('any')

        addr_list = []
        if address:
            for item in address:
                prefix = item.split('/')[0]
                len = item.split('/')[1]
                addr_list.append(vnc_api.AddressType(
                        subnet = vnc_api.SubnetType(
                        ip_prefix = prefix, ip_prefix_len = int(len))))
        else:
            addr_list.append(vnc_api.AddressType(
                    subnet = vnc_api.SubnetType(
                    ip_prefix = '0.0.0.0', ip_prefix_len = 0)))

        local_addr_list = [vnc_api.AddressType(security_group = 'local')]

        port_list = []
        if port:
            for item in port:
                if (item == 'any'):
                    port_list.append(vnc_api.PortType(
                            start_port = -1, end_port = -1))
                else:
                    s_e = item.split(':')
                    port_list.append(vnc_api.PortType(
                            start_port = int(s_e[0]), end_port = int(s_e[1])))
        else:
            port_list.append(vnc_api.PortType(start_port = -1, end_port = -1))

        local_port_list = [vnc_api.PortType(start_port = -1, end_port = -1)]

        if (direction == 'ingress'):
            rule.set_src_addresses(addr_list)
            rule.set_src_ports(port_list)
            rule.set_dst_addresses(local_addr_list)
            rule.set_dst_ports(local_port_list)
        else:
            rule.set_src_addresses(local_addr_list)
            rule.set_src_ports(local_port_list)
            rule.set_dst_addresses(addr_list)
            rule.set_dst_ports(port_list)

        obj = self.obj_get(name)
        if obj:
            rules = obj.get_security_group_entries()
            if not rules:
                rules = vnc_api.PolicyEntriesType(policy_rule = [rule])
            else:
                rules.add_policy_rule(rule)
            try:
                self.vnc.security_group_update(obj)
            except Exception as e:
                print 'ERROR: %s' %(str(e))
        else:
            rules = vnc_api.PolicyEntriesType(policy_rule = [rule])
            obj = vnc_api.SecurityGroup(name = name,
                    parent_obj = self.tenant,
                    security_group_entries = rules)
            try:
                self.vnc.security_group_create(obj)
            except Exception as e:
                print 'ERROR: %s' %(str(e))

    def delete_rule(self, obj, index):
        rules = obj.get_security_group_entries()
        if not rules:
            return
        rule = rules.get_policy_rule()[index - 1]
        rules.delete_policy_rule(rule)
        self.vnc.security_group_update(obj)

    def delete(self, name, rule = None):
        obj = self.obj_get(name, msg = True)
        if not obj:
            return
        if rule:
            self.delete_rule(obj, int(rule))
        else:
            try:
                self.vnc.security_group_delete(id = obj.uuid)
            except Exception as e:
                print 'ERROR: %s' %(str(e))


class ConfigNetwork(ConfigObject):
    def __init__(self, client):
        super(ConfigNetwork, self).__init__(client,
                ['default-domain', client.tenant.name],
                client.vnc.virtual_network_read,
                client.vnc.virtual_networks_list)

    def show_prop_route_target(self, obj):
        print '[P] Route targets:'
        rt_list = obj.get_route_target_list()
        if not rt_list:
            return
        for rt in rt_list.get_route_target():
            print '    %s' %(rt)

    def show_child_floating_ip_pool(self, obj):
        print '[C] Floating IP pools:'
        pool_list = obj.get_floating_ip_pools()
        if not pool_list:
            return
        for pool in pool_list:
            print '    %s' %(pool['to'][3])
            pool_obj = self.vnc.floating_ip_pool_read(id = pool['uuid'])
            ip_list = pool_obj.get_floating_ips()
            if (ip_list != None):
                for ip in ip_list:
                    ip_obj = self.vnc.floating_ip_read(id = ip['uuid'])
                    print '        %s' %(ip_obj.get_floating_ip_address())

    def show_ref_ipam(self, obj):
        print '[R] IPAMs:'
        ipam_list = obj.get_network_ipam_refs()
        if not ipam_list:
            return
        for item in ipam_list:
            print '    %s' %(item['to'][2])
            subnet_list = item['attr'].get_ipam_subnets()
            for subnet in subnet_list:
                print '        subnet: %s/%d, gateway: %s' %(
                        subnet.get_subnet().get_ip_prefix(),
                        subnet.get_subnet().get_ip_prefix_len(),
                        subnet.get_default_gateway())

    def show_ref_policy(self, obj):
        print '[R] Policies:'
        policy_list = obj.get_network_policy_refs()
        if not policy_list:
            return
        for item in policy_list:
            print '    %s (%d.%d)' %(item['to'][2],
                    item['attr'].get_sequence().get_major(),
                    item['attr'].get_sequence().get_minor())

    def show_ref_route_table(self, obj):
        print '[R] Route Tables:'
        rt_list = obj.get_route_table_refs()
        if not rt_list:
            return
        for item in rt_list:
            print '    %s' %(item['to'][2])

    def show_obj(self, obj):
        print '## Virtual Network'
        print 'Name: %s' %(obj.get_fq_name())
        print 'UUID: %s' %(obj.uuid)
        self.show_prop_route_target(obj)
        self.show_child_floating_ip_pool(obj)
        self.show_ref_ipam(obj)
        self.show_ref_policy(obj)
        self.show_ref_route_table(obj)

    def add_ipam(self, obj, name, subnet, gateway = None):
        try:
            ipam_obj = self.vnc.network_ipam_read(
                    fq_name = self.fq_name_get(name))
        except Exception as e:
            print 'ERROR: %s' %(str(e))
            return
        cidr = subnet.split('/')
        subnet = vnc_api.SubnetType(ip_prefix = cidr[0],
                ip_prefix_len = int(cidr[1]))
        ipam_subnet = vnc_api.IpamSubnetType(subnet = subnet,
                default_gateway = gateway)

        ipam_list = obj.get_network_ipam_refs()
        subnet_list = []
        if ipam_list:
            for item in ipam_list:
                if item['to'] == ipam_obj.get_fq_name():
                    subnet_list = item['attr'].get_ipam_subnets()
                    obj.del_network_ipam(ref_obj = ipam_obj)   
                    break
        subnet_list.append(ipam_subnet)
        obj.add_network_ipam(ref_obj = ipam_obj,    
                ref_data = vnc_api.VnSubnetsType(subnet_list))

    def ipam_del(self, obj, name):
        try:
            ipam_obj = self.vnc.network_ipam_read(
                    fq_name = self.fq_name_get(name))
        except Exception as e:
            print 'ERROR: %s' %(str(e))
            return
        obj.del_network_ipam(ref_obj = ipam_obj)

    def add_policy(self, obj, name):
        try:
            policy_obj = self.vnc.network_policy_read(
                    fq_name = self.fq_name_get(name))
        except Exception as e:
            print 'ERROR: %s' %(str(e))
            return
        seq = vnc_api.SequenceType(major = 0, minor = 0)
        obj.add_network_policy(ref_obj = policy_obj,
                ref_data = vnc_api.VirtualNetworkPolicyType(sequence = seq))

    def policy_del(self, obj, name):
        try:
            policy_obj = self.vnc.network_policy_read(
                    fq_name = self.fq_name_get(name))
        except Exception as e:
            print 'ERROR: %s' %(str(e))
            return
        obj.del_network_policy(ref_obj = policy_obj)

    def add_route_target(self, obj, rt):
        rt_list = obj.get_route_target_list()
        if not rt_list:
            rt_list = vnc_api.RouteTargetList()
            obj.set_route_target_list(rt_list)
        rt_list.add_route_target('target:%s' %(rt))

    def route_target_del(self, obj, rt):
        rt_list = obj.get_route_target_list()
        if not rt_list:
            return
        rt_list.delete_route_target('target:%s' %(rt))

    def add_route_table(self, obj, rt):
        try:
            rt_obj = self.vnc.route_table_read(
                    fq_name = self.fq_name_get(name))
        except Exception as e:
            print 'ERROR: %s' %(str(e))
            return
        obj.add_route_table(ref_obj = rt_obj)

    def route_table_del(self, obj, rt):
        try:
            rt_obj = self.vnc.route_table_read(
                    fq_name = self.fq_name_get(name))
        except Exception as e:
            print 'ERROR: %s' %(str(e))
            return
        obj.del_route_table(ref_obj = rt_obj)

    def add(self, name, ipam = None, subnet = None, policy = None,
            route_target = None, route_table = None, shared = None,
            external = None, l2 = None):
        create = False
        obj = self.obj_get(name)
        if not obj:
            obj = vnc_api.VirtualNetwork(name = name, parent_obj = self.tenant)
            if l2:
                prop = vnc_api.VirtualNetworkType(forwarding_mode = 'l2')
                obj.set_virtual_network_properties(prop)
            if shared:
                obj.set_is_shared(shared)
            if external:
                obj.set_router_external(external)
            create = True
        if ipam and subnet:
            self.add_ipam(obj, ipam, subnet)
        if policy:
            self.add_policy(obj, policy)
        if route_target:
            self.add_route_target(obj, route_target)
        if route_table:
            self.add_route_table(obj, route_table)
        if create:
            try:
                self.vnc.virtual_network_create(obj)
            except Exception as e:
                print 'ERROR: %s' %(str(e))
        else:
            self.vnc.virtual_network_update(obj)

    def delete(self, name, ipam = None, policy = None, route_target = None,
            route_table = None):
        update = False
        obj = self.obj_get(name, msg = True)
        if not obj:
            return
        if ipam:
            self.ipam_del(obj, ipam)
            update = True
        if policy:
            self.policy_del(obj, policy)
            update = True
        if route_target:
            self.route_target_del(obj, route_target)
            update = True
        if route_table:
            self.route_table_del(obj, route_table)
            update = True
        if update:
            self.vnc.virtual_network_update(obj)
        else:
            try:
                self.vnc.virtual_network_delete(id = obj.uuid)
            except Exception as e:
                print 'ERROR: %s' %(str(e))


class ConfigFloatingIpPool(ConfigObject):
    def __init__(self, client):
        super(ConfigFloatingIpPool, self).__init__(client,
                ['default-domain', client.tenant.name],
                client.vnc.floating_ip_pool_read,
                client.vnc.floating_ip_pools_list)

    def show_prop_subnet(self, obj):
        print '[P] Subnet:'
        prefixes = obj.get_floating_ip_pool_prefixes()
        if not prefixes:
            return
        for item in prefixes.get_subnet():
            print '    %s/%s' %(item.get_ip_prefix(), item.get_ip_prefix_len())

    def show_child_ip(self, obj):
        print '[C] Floating IPs:'
        list = obj.get_floating_ips()
        if not list:
            return
        for ip in list:
            ip_obj = self.vnc.floating_ip_read(id = ip['uuid'])
            print '    %s' %(ip_obj.get_floating_ip_address())

    def show_back_ref_tenant(self, obj):
        print '[BR] Tenants:'
        list = obj.get_project_back_refs()
        if not list:
            return
        for item in list:
            print '    %s' %(item['to'][1])

    def show_obj(self, obj):
        print '## Floating IP Pool'
        print 'Name: %s' %(obj.get_fq_name())
        print 'UUID: %s' %(obj.uuid)
        self.show_prop_subnet(obj)
        self.show_child_ip(obj)
        self.show_back_ref_tenant(obj)

    def add(self, name, network):
        name_list = name.split(':')
        if (len(name_list) != 2):
            print 'ERROR: Name format is incorrect!'
            return
        try:
            net_obj = self.vnc.virtual_network_read(
                    fq_name = self.fq_name_get(name_list[0]))
        except:
            print 'ERROR: Virtual network %s is not found!' %(name_list[0])
            return
        obj = vnc_api.FloatingIpPool(name = name_list[1], parent_obj = net_obj)
        try:
            self.vnc.floating_ip_pool_create(obj)
            self.tenant.add_floating_ip_pool(obj)
            self.vnc.project_update(self.tenant)
        except Exception as e:
            print 'ERROR: %s' %(str(e))

    def delete_fip(self, pool_obj):
        pass

    def delete(self, name, network):
        name_list = name.split(':')
        if (len(name_list) != 2):
            print 'ERROR: Name format is incorrect!'
            return
        obj = self.obj_get(name, msg = True)
        if not obj:
            return
        if obj.get_floating_ips():
            print 'ERROR: There are allocated floating IPs!'
            return
        for tenant_ref in obj.get_project_back_refs():
            tenant = self.vnc.project_read(fq_name = tenant_ref['to'])
            tenant.del_floating_ip_pool(obj)
            self.vnc.project_update(tenant)
        try:
            self.vnc.floating_ip_pool_delete(id = obj.uuid)
        except Exception as e:
            print 'ERROR: %s' %(str(e))


class ConfigServiceTemplate(ConfigObject):
    def __init__(self, client):
        super(ConfigServiceTemplate, self).__init__(client,
                ['default-domain'],
                client.vnc.service_template_read,
                client.vnc.service_templates_list)

    def show_obj(self, obj):
        print '## Service Template'
        print 'Name: %s' %(obj.get_fq_name())
        print 'UUID: %s' %(obj.uuid)
        properties = obj.get_service_template_properties()
        print 'Service Mode: %s' %(properties.get_service_mode())
        print 'Service Type: %s' %(properties.get_service_type())
        print 'Service Image: %s' %(properties.get_image_name())
        print 'Service Flavor: %s' %(properties.get_flavor())
        print 'Service Interfaces:'
        for item in properties.get_interface_type():
            print '    %s' %(item.get_service_interface_type())

    def add(self, name, mode, type, image, flavor, interface_type,
            scale = None):
        obj = vnc_api.ServiceTemplate(name = name)
        properties = vnc_api.ServiceTemplateType(service_mode = mode,
                service_type = type, image_name = image, flavor = flavor,
                ordered_interfaces = True, availability_zone_enable = True)
        if scale:
            properties.set_service_scaling(scale)
            for item in interface_type:
                if (mode == 'transparent') and \
                       ((item == 'left') or (item == 'right')):
                    shared_ip = True
                elif (mode == 'in-network') and (item == 'left'):
                    shared_ip = True
                else:
                    shared_ip = False
                type = vnc_api.ServiceTemplateInterfaceType(
                        service_interface_type = item,
                        shared_ip = shared_ip,
                        static_route_enable = True)
                properties.add_interface_type(type)
        else:
            for item in interface_type:
                type = vnc_api.ServiceTemplateInterfaceType(
                        service_interface_type = item,
                        static_route_enable = True)
                properties.add_interface_type(type)
        obj.set_service_template_properties(properties)
        try:
            self.vnc.service_template_create(obj)
        except Exception as e:
            print 'ERROR: %s' %(str(e))

    def delete(self, name):
        obj = self.obj_get(name, msg = True)
        if not obj:
            return
        try:
            self.vnc.service_template_delete(id = obj.uuid)
        except Exception as e:
            print 'ERROR: %s' %(str(e))


class ConfigServiceInstance(ConfigObject):
    def __init__(self, client):
        super(ConfigServiceInstance, self).__init__(client,
                ['default-domain', client.tenant.name],
                client.vnc.service_instance_read,
                client.vnc.service_instances_list)

    def show_obj(self, obj):
        print '## Service Instance'
        print 'Name: %s' %(obj.get_fq_name())
        print 'UUID: %s' %(obj.uuid)

    def add(self, name, template, network_list,
            auto_policy = None, scale_max = None):
        obj = vnc_api.ServiceInstance(name = name, parent_obj = self.tenant)
        properties = vnc_api.ServiceInstanceType(auto_policy = auto_policy)
        for net in network_list:
            net_name = None
            net_route = None
            net_auto = False
            tenant_name = self.tenant.name
            for arg in net.split(','):
                arg_name = arg.split('=')[0]
                arg_val = arg.split('=')[1]
                if (arg_name == 'tenant'):
                    tenant_name = arg_val
                elif (arg_name == 'network'):
                    if (arg_val == 'auto'):
                        net_auto = True
                    else:
                        net_name = arg_val
                elif (arg_name == 'route'):
                    net_route = arg_val
            if net_auto:
                net_fq_name = None
            else:
                net_fq_name = 'default-domain:%s:%s' %(tenant_name, net_name)
            interface = vnc_api.ServiceInstanceInterfaceType(
                    virtual_network = net_fq_name)
            if net_route:
                route = vnc_api.RouteType(prefix = net_route)
                route_table = vnc_api.RouteTableType()
                route_table.add_route(route)
                interface.set_static_routes(route_table)
            properties.add_interface_list(interface)

        if scale_max:
            scale = vnc_api.ServiceScaleOutType(
                    max_instances = int(scale_max),
                    auto_scale = True)
        else:
            scale = vnc_api.ServiceScaleOutType()
        properties.set_scale_out(scale)

        obj.set_service_instance_properties(properties)
        try:
            template = self.vnc.service_template_read(
                    fq_name = ['default-domain', template])
        except Exception as e:
            print 'ERROR: %s' %(str(e))
        obj.set_service_template(template)
        try:
            self.vnc.service_instance_create(obj)
        except Exception as e:
            print 'ERROR: %s' %(str(e))

    def delete(self, name):
        obj = self.obj_get(name, msg = True)
        if not obj:
            return
        try:
            self.vnc.service_instance_delete(id = obj.uuid)
        except Exception as e:
            print 'ERROR: %s' %(str(e))


class ConfigRouteTable(ConfigObject):
    def __init__(self, client):
        super(ConfigRouteTable, self).__init__(client,
                ['default-domain', client.tenant.name],
                client.vnc.route_table_read,
                client.vnc.route_tables_list)

    def show_obj(self, obj):
        print '## Route Table'
        print 'Name: %s' %(obj.get_fq_name())
        print 'UUID: %s' %(obj.uuid)
        routes = obj.get_routes()
        if not routes:
            return
        for item in routes.get_route():
            print '  %s next-hop %s' %(item.get_prefix(), item.get_next_hop())

    def add_route(self, obj, route_args):
        routes = obj.get_routes()
        if not routes:
            routes = vnc_api.RouteTableType()
            obj.set_routes(routes)
        for arg in route_args.split(','):
            arg_name = arg.split('=')[0]
            arg_val = arg.split('=')[1]
            if (arg_name == 'prefix'):
                prefix = arg_val
            elif (arg_name == 'next-hop'):
                nh = 'default-domain:%s:%s' %(self.tenant.name, arg_val)
        routes.add_route(vnc_api.RouteType(prefix = prefix, next_hop = nh))

    def add(self, name, route_list = None):
        create = False
        obj = self.obj_get(name)
        if not obj:
            obj = vnc_api.RouteTable(name = name, parent_obj = self.tenant)
            create = True
        if route_list:
            for item in route_list:
                self.add_route(obj, item)
        if create:
            try:
                self.vnc.route_table_create(obj)
            except Exception as e:
                print 'ERROR: %s' %(str(e))
        else:
            self.vnc.route_table_update(obj)

    def delete_route(self, obj, route_args):
        routes = obj.get_routes()
        if not routes:
            return
        for arg in route_args.split(','):
            arg_name = arg.split('=')[0]
            arg_val = arg.split('=')[1]
            if (arg_name == 'prefix'):
                prefix = arg_val
        for item in routes.get_route():
            if (item.get_prefix() == prefix):
                routes.delete_route(item)
        routes = obj.set_routes(routes)

    def delete(self, name, route_list = None):
        obj = self.obj_get(name, msg = True)
        if not obj:
            return
        if route_list:
            for item in route_list:
                self.delete_route(obj, item)
            self.vnc.route_table_update(obj)
        else:
            try:
                self.vnc.route_table_delete(id = obj.uuid)
            except Exception as e:
                print 'ERROR: %s' %(str(e))


class ConfigInterfaceRouteTable(ConfigObject):
    def __init__(self, client):
        super(ConfigInterfaceRouteTable, self).__init__(client,
                ['default-domain', client.tenant.name],
                client.vnc.interface_route_table_read,
                client.vnc.interface_route_tables_list)

    def show_obj(self, obj):
        print '## Interface Route Table'
        print 'Name: %s' %(obj.get_fq_name())
        print 'UUID: %s' %(obj.uuid)
        try:
            af = obj.get_interface_route_table_family()
            print 'Address Family: %s' %(af)
        except:
            pass
        routes = obj.get_interface_route_table_routes()
        if not routes:
            return
        for item in routes.get_route():
            print '  %s' %(item.get_prefix())

    def add_route(self, obj, prefix):
        routes = obj.get_interface_route_table_routes()
        if not routes:
            routes = vnc_api.RouteTableType()
        routes.add_route(vnc_api.RouteType(prefix = prefix))
        obj.set_interface_route_table_routes(routes)

    def add(self, name, route_list = None, af = None):
        create = False
        obj = self.obj_get(name)
        if not obj:
            obj = vnc_api.InterfaceRouteTable(name = name,
                    parent_obj = self.tenant)
            create = True
        if route_list:
            for item in route_list:
                self.add_route(obj, item)
        if af:
            if af == 'ipv4':
                obj.set_interface_route_table_family('v4')
            elif af == 'ipv6':
                obj.set_interface_route_table_family('v6')
        if create:
            try:
                self.vnc.interface_route_table_create(obj)
            except Exception as e:
                print 'ERROR: %s' %(str(e))
        else:
            self.vnc.interface_route_table_update(obj)

    def delete_route(self, obj, prefix):
        routes = obj.get_interface_route_table_routes()
        if not routes:
            return
        for item in routes.get_route():
            if (item.get_prefix() == prefix):
                routes.delete_route(item)
        obj.set_interface_route_table_routes(routes)

    def delete(self, name, route = None):
        obj = self.obj_get(name, msg = True)
        if not obj:
            return
        if route:
            for item in route:
                self.delete_route(obj, item)
            self.vnc.interface_route_table_update(obj)
        else:
            try:
                self.vnc.interface_route_table_delete(id = obj.uuid)
            except Exception as e:
                print 'ERROR: %s' %(str(e))


class ConfigPort(ConfigObject):
    def __init__(self, client):
        super(ConfigPort, self).__init__(client,
                ['default-domain', client.tenant.name],
                client.vnc.virtual_machine_interface_read,
                client.vnc.virtual_machine_interfaces_list)

    def show_ref_network(self, obj):
        print '[R] Virtual Network:'
        ref_list = obj.get_virtual_network_refs()
        if not ref_list:
            return
        for item in ref_list:
            print '    %s' %(item['to'][2])

    def show_ref_vm(self, obj):
        print '[R] Virtual Machine:'
        ref_list = obj.get_virtual_machine_refs()
        if not ref_list:
            return
        for item in ref_list:
            print '    %s' %(item['to'][0])

    def show_back_ref_ip(self, obj):
        print '[BR] Instance IP:'
        ref_list = obj.get_instance_ip_back_refs()
        if not ref_list:
            return
        for item in ref_list:
            ip_obj = self.vnc.instance_ip_read(id = item['to'][0])
            print '    %s' %(ip_obj.get_instance_ip_address())

    def show_obj(self, obj):
        print '## Port'
        print 'Name: %s' %(obj.get_fq_name())
        print 'UUID: %s' %(obj.uuid)
        print 'MAC Address: %s' %(
                obj.get_virtual_machine_interface_mac_addresses(
                ).get_mac_address())
        self.show_ref_vm(obj)
        self.show_ref_network(obj)
        self.show_back_ref_ip(obj)

    def add(self, name, network, address, shared):
        update = False
        if name == 'auto':
            id = str(uuid.uuid4())
            port_obj = vnc_api.VirtualMachineInterface(name = id, 
                    parent_obj = self.tenant)
            port_obj.uuid = id
        else:
            port_obj = self.obj_get(name)
            if port_obj:
                update= True
            else:
                port_obj = vnc_api.VirtualMachineInterface(name = name, 
                        parent_obj = self.tenant)

        net_obj = self.vnc.virtual_network_read(
                fq_name = ['default-domain', self.tenant.name, network])
        if not update:
            port_obj.set_virtual_network(net_obj)
            self.vnc.virtual_machine_interface_create(port_obj)

        ip_obj = vnc_api.InstanceIp(name = str(uuid.uuid4()))
        ip_obj.uuid = ip_obj.name
        ip_obj.add_virtual_network(net_obj)
        if address:
            ip_obj.set_instance_ip_address(address)
            if (len(address.split(':')) > 1):
                ip_obj.set_instance_ip_family('v6')
            else:
                ip_obj.set_instance_ip_family('v4')
        if shared:
            ip_obj.set_instance_ip_mode(u'active-active')
        ip_obj.add_virtual_machine_interface(port_obj)
        self.vnc.instance_ip_create(ip_obj)

        print port_obj.uuid

    def delete(self, name, network, address):
        update = False
        obj = self.obj_get(name, msg = True)
        if not obj:
            return
        if address:
            for item in obj.get_instance_ip_back_refs():
                ip_obj = self.vnc.instance_ip_read(id = item['uuid'])
                if (ip_obj.get_instance_ip_address() == address):
                    self.vnc.instance_ip_delete(id = item['uuid'])
                    break
            update = True

        if not update:
            for item in obj.get_instance_ip_back_refs():
                self.vnc.instance_ip_delete(id = item['uuid'])
            self.vnc.virtual_machine_interface_delete(id = obj.uuid)


class ConfigVmInterface():
    def __init__(self, client):
        self.vnc = client.vnc
        self.tenant = client.tenant
        self.nova = client.nova

    def obj_list(self, vm_id = None):
        list = []
        if vm_id:
            vm = self.vnc.virtual_machine_read(id = vm_id)
            if_ref_list = vm.get_virtual_machine_interface_back_refs()
            for if_ref in if_ref_list:
                if_obj = self.vnc.virtual_machine_interface_read(
                        id = if_ref['uuid'])
                vn_name = if_obj.get_virtual_network_refs()[0]['to'][2]
                list.append({'name':vn_name, 'uuid':if_ref['uuid'],
                        'obj':if_obj})
        else:
            for vm_nova in self.nova.servers.list():
                try:
                    vm = self.vnc.virtual_machine_read(id = vm_nova.id)
                except:
                    print 'WARN: VM %s is not found.' %(vm_nova.id)
                    continue
                if_ref_list = vm.get_virtual_machine_interface_back_refs()
                for if_ref in if_ref_list:
                    if_obj = self.vnc.virtual_machine_interface_read(
                            id = if_ref['uuid'])
                    vn_name = if_obj.get_virtual_network_refs()[0]['to'][2]
                    list.append({'name':'%s:%s' %(vm_nova.name, vn_name),
                            'uuid':if_ref['uuid'], 'obj':if_obj})
        return list

    def obj_get(self, name, vm_id = None):
        list = self.obj_list(vm_id)
        for item in list:
            if (item['name'] == name):
                return item['obj']

    def prop_mac_show(self, obj):
        print '[P] MAC addresses:'
        mac = obj.get_virtual_machine_interface_mac_addresses()
        if not mac:
            return
        for item in mac.get_mac_address():
            print '    %s' %(item)

    def prop_prop_show(self, obj):
        prop = obj.get_virtual_machine_interface_properties()
        if not prop:
            return
        print '[P] Service interface type: %s' \
                %(prop.get_service_interface_type())
        print '[P] Interface mirror: %s' %(prop.get_interface_mirror())

    def ref_sg_show(self, obj):
        print '[R] Security groups:'
        refs = obj.get_security_group_refs()
        if refs:
            for item in obj.get_security_group_refs():
                print '    %s' %(item['to'][2])

    def ref_net_show(self, obj):
        print '[R] Virtual networks:'
        for item in obj.get_virtual_network_refs():
            print '    %s' %(item['to'][2])

    def ref_irt_show(self, obj):
        print '[R] Interface route tables:'
        list = obj.get_interface_route_table_refs()
        if list:
            for item in list:
                print '    %s' %(item['to'][2])

    def back_ref_ip_show(self, obj):
        print '[BR] Instance IPs:'
        list = obj.get_instance_ip_back_refs()
        if not list:
            return
        for item in list:
            ip = self.vnc.instance_ip_read(id = item['uuid'])
            print '    %s' %(ip.get_instance_ip_address())

    def back_ref_fip_show(self, obj):
        print '[BR] Floating IPs:'
        list = obj.get_floating_ip_back_refs()
        if not list:
            return
        for item in list:
            ip = self.vnc.floating_ip_read(id = item['uuid'])
            print '    %s' %(ip.get_floating_ip_address())

    def show_obj(self, obj):
        print 'Virtual Machine Interface'
        print 'Name: %s' %(obj.get_fq_name())
        print 'UUID: %s' %(obj.uuid)
        self.prop_mac_show(obj)
        self.prop_prop_show(obj)
        self.ref_sg_show(obj)
        self.ref_net_show(obj)
        self.ref_irt_show(obj)
        self.back_ref_ip_show(obj)
        self.back_ref_fip_show(obj)

    def show(self, args):
        if args.name:
            obj = self.obj_get(args.name)
            if not obj:
                print 'ERROR: Object %s is not found!' %(args.name)
                return
            self.show_obj(obj)
        else:
            for item in self.obj_list():
                    print '    %s' %(item['name'])

    def add_sg(self, obj, sg):
        try:
            sg_obj = self.vnc.security_group_read(
                    fq_name = ['default-domain', self.tenant.name, sg])
        except Exception as e:
            print 'ERROR: %s' %(str(e))
            return
        obj.add_security_group(sg_obj)

    def add_addr(self, obj, addr):
        id = str(uuid.uuid4())
        ip_obj = vnc_api.InstanceIp(name = id, instance_ip_address = addr)
        ip_obj.uuid = id
        ip_obj.add_virtual_machine_interface(obj)
        vn_id = obj.get_virtual_network_refs()[0]['uuid']
        vn_obj = self.vnc.virtual_network_read(id = vn_id)
        ip_obj.add_virtual_network(vn_obj)
        self.vnc.instance_ip_create(ip_obj)

    def add_irt(self, obj, irt):
        try:
            table_obj = self.vnc.interface_route_table_read(
                    fq_name = ['default-domain', self.tenant.name, irt])
        except Exception as e:
            print 'ERROR: %s' %(str(e))
            return
        obj.add_interface_route_table(table_obj)

    def add_fip(self, obj, fip_pool, fip):
        pool_name = fip_pool.split(':')
        pool_name.insert(0, 'default-domain')
        try:
            pool_obj = self.vnc.floating_ip_pool_read(fq_name = pool_name)
        except Exception as e:
            print 'ERROR: %s' %(str(e))
            return
        id = str(uuid.uuid4())
        fip_obj = vnc_api.FloatingIp(name = id, parent_obj = pool_obj)
        fip_obj.uuid = id
        if (fip != 'any'):
            fip_obj.set_floating_ip_address(fip)
        fip_obj.add_project(self.tenant)
        fip_obj.add_virtual_machine_interface(obj)
        self.vnc.floating_ip_create(fip_obj)
        self.tenant.add_floating_ip_pool(pool_obj)
        self.vnc.project_update(self.tenant)

    def add(self, name, sg = None, irt = None, addr = None,
            fip_pool = None, fip = None):
        update = False
        obj = self.obj_get(name)
        if not obj:
            print 'ERROR: Object %s is not found!' %(name)
            return
        if sg:
            self.add_sg(obj, sg)
            update = True
        if irt:
            self.add_irt(obj, irt)
            update = True
        if addr:
            self.add_addr(obj, addr)
            update = True
        if fip and fip_pool:
            self.add_fip(obj, fip_pool, fip)
            update = True
        if update:
            self.vnc.virtual_machine_interface_update(obj)

    def delete_sg(self, obj, sg):
        obj.set_security_group_list([])
        '''
        try:
            sg_obj = self.vnc.security_group_read(
                    fq_name = ['default-domain', self.tenant.name, sg])
        except Exception as e:
            print 'ERROR: %s' %(str(e))
            return
        obj.del_security_group(sg_obj)
        '''

    def delete_irt(self, obj, irt):
        try:
            table_obj = self.vnc.interface_route_table_read(
                    fq_name = ['default-domain', self.tenant.name, irt])
        except Exception as e:
            print 'ERROR: %s' %(str(e))
            return
        obj.del_interface_route_table(table_obj)

    def delete_addr(self, obj, addr):
        ip_list = obj.get_instance_ip_back_refs()
        for ip in ip_list:
            ip_obj = self.vnc.instance_ip_read(id = ip['uuid'])
            if (ip_obj.get_instance_ip_address() == addr):
                self.vnc.instance_ip_delete(id = ip_obj.uuid)
                break
        else:
            print 'ERROR: IP address %s is not found!' %(addr)

    def delete_fip(self, obj):
        list = obj.get_floating_ip_back_refs()
        if not list:
            return
        for item in list:
            ip = self.vnc.floating_ip_delete(id = item['uuid'])

    def delete(self, name, sg = None, irt = None, addr = None,
            fip = None, vm_id = None):
        update = False
        obj = self.obj_get(name, vm_id)
        if not obj:
            print 'ERROR: Object %s is not found!' %(name)
            return
        if sg:
            self.delete_sg(obj, sg)
            update = True
        if irt:
            self.delete_irt(obj, irt)
            update = True
        if addr:
            self.delete_addr(obj, addr)
            update = True
        if fip:
            self.delete_fip(obj)
            update = True
        if update:
            self.vnc.virtual_machine_interface_update(obj)


class ConfigVirtualDns():
    def __init__(self, client):
        self.vnc = client.vnc
        self.tenant = client.tenant

    def obj_list(self):
        list = self.vnc.virtual_DNSs_list()['virtual-DNSs']
        return list

    def obj_get(self, name):
        for item in self.obj_list():
            if (item['fq_name'][1] == name):
                return self.vnc.virtual_DNS_read(id = item['uuid'])

    def show_obj(self, obj):
        print 'Virtual DNS'
        print 'Name: %s' %(obj.get_fq_name())
        print 'UUID: %s' %(obj.uuid)
        dns = obj.get_virtual_DNS_data()
        print 'Domain name: %s' %(dns.domain_name)
        print 'Record order: %s' %(dns.record_order)
        print 'Default TTL: %s seconds' %(dns.default_ttl_seconds)
        print 'Next DNS: %s' %(dns.next_virtual_DNS)

    def show(self, args):
        if args.name:
            obj = self.obj_get(args.name)
            if not obj:
                print 'ERROR: Object %s is not found!' %(args.name)
                return
            self.show_obj(obj)
        else:
            for item in self.obj_list():
                print '    %s' %(item['fq_name'][1])

    def add(self, name, domain_name, record_order, next_dns):
        data = vnc_api.VirtualDnsType(domain_name = domain_name,
                dynamic_records_from_client = True,
                record_order = record_order,
                default_ttl_seconds = 86400,
                next_virtual_DNS = 'default-domain:' + next_dns)
        obj = vnc_api.VirtualDns(name = name, virtual_DNS_data = data)
        try:
            self.vnc.virtual_DNS_create(obj)
        except Exception as e:
            print 'ERROR: %s' %(str(e))

    def delete(self, name):
        try:
            self.vnc.virtual_DNS_delete(
                    fq_name = ['default-domain', name])
        except Exception as e:
            print 'ERROR: %s' %(str(e))


class ConfigBgpRouter(ConfigObject):
    def __init__(self, client):
        super(ConfigBgpRouter, self).__init__(client,
                ['default-domain', 'default-project', 'ip-fabric',
                '__default__',],
                client.vnc.bgp_router_read,
                client.vnc.bgp_routers_list)

    def show_ref_bgp_router(self, obj):
        print '[R] BGP Peers:'
        ref_list = obj.get_bgp_router_refs()
        if not ref_list:
            return
        for item in ref_list:
            print '        %s' %(item['to'][4])

    def show_obj(self, obj):
        print '## BGP Router'
        print 'Name: %s' %(obj.get_fq_name())
        print 'UUID: %s' %(obj.uuid)
        prop = obj.get_bgp_router_parameters()
        print 'Vendor: %s' %(prop.vendor)
        print 'ASN: %d' %(prop.autonomous_system)
        print 'Address: %s' %(prop.address)
        print 'Identifier: %s' %(prop.identifier)
        print 'Port: %s' %(prop.port)
        print 'Hold Time: %s' %(prop.hold_time)
        print 'Address Families:'
        for item in prop.get_address_families().get_family():
            print '        %s' %(item)
        self.show_ref_bgp_router(obj)

    def add(self, name, vendor = None, asn = None, address = None,
            identifier = None, control = None):
        if not identifier:
            identifier = address
        if control:
            af = vnc_api.AddressFamilies(['route-target', 'inet-vpn', 'e-vpn',
                    'erm-vpn'])
        else:
            af = vnc_api.AddressFamilies(['route-target', 'inet-vpn'])

        ri = self.vnc.routing_instance_read(fq_name=['default-domain',
                'default-project', 'ip-fabric', '__default__'])
        params = vnc_api.BgpRouterParams(vendor = vendor,
                autonomous_system = int(asn), identifier = identifier,
                address = address, port = 179, address_families = af)
        obj = vnc_api.BgpRouter(name, ri, bgp_router_parameters = params)

        try:
            id = self.vnc.bgp_router_create(obj)
        except Exception as e:
            print 'ERROR: %s' %(str(e))
            return

        obj = self.vnc.bgp_router_read(id = id)

        sess_attr_list = [vnc_api.BgpSessionAttributes(address_families = af)]
        sess_list = [vnc_api.BgpSession(attributes = sess_attr_list)]
        peering_attrs = vnc_api.BgpPeeringAttributes(session = sess_list)

        peer_list = self.vnc.bgp_routers_list()['bgp-routers']
        peer_id_list = []
        for peer in peer_list:
            peer_id_list.append(peer['uuid'])

        peer_obj_list = []
        for item in peer_id_list:
            peer_obj_list.append(self.vnc.bgp_router_read(id = item))

        for item in peer_obj_list:
            if (item.uuid == id):
                continue
            obj.add_bgp_router(item, peering_attrs)

        self.vnc.bgp_router_update(obj)

    def delete(self, name):
        obj = self.obj_get(name, msg = True)
        if not obj:
            return
        self.vnc.bgp_router_delete(id = obj.uuid)


class ConfigGlobalVrouter(ConfigObject):
    def __init__(self, client):
        super(ConfigGlobalVrouter, self).__init__(client,
                ['default-global-system-config'],
                client.vnc.global_vrouter_config_read,
                client.vnc.global_vrouter_configs_list)

    def show_obj(self, obj):
        print '## Global vRouter'
        print 'Name: %s' %(obj.get_fq_name())
        print 'UUID: %s' %(obj.uuid)
        print 'Linklocal Service:'
        for item in obj.get_linklocal_services().get_linklocal_service_entry():
            print '  %s  %s:%s  %s:%s' %(item.get_linklocal_service_name(),
                    item.get_linklocal_service_ip(),
                    item.get_linklocal_service_port(),
                    item.get_ip_fabric_service_ip(),
                    item.get_ip_fabric_service_port())

    def add_linklocal(self, obj, args_list):
        linklocal = obj.get_linklocal_services()
        if not linklocal:
            linklocal = vnc_api.LinklocalServicesTypes()
        linklocal_list = linklocal.get_linklocal_service_entry()
        for args in args_list:
            for arg in args.split(','):
                arg_name = arg.split('=')[0]
                arg_val = arg.split('=')[1]
                if (arg_name == 'name'):
                    name = arg_val
                elif (arg_name == 'linklocal-address'):
                    linklocal_addr = arg_val.split(':')[0]
                    linklocal_port = arg_val.split(':')[1]
                elif (arg_name == 'fabric-address'):
                    fabric_addr = arg_val.split(':')[0]
                    fabric_port = arg_val.split(':')[1]
            linklocal_list.append(vnc_api.LinklocalServiceEntryType(
                    linklocal_service_name = name,
                    linklocal_service_ip = linklocal_addr,
                    linklocal_service_port = int(linklocal_port),
                    ip_fabric_service_ip = fabric_addr,
                    ip_fabric_service_port = int(fabric_port)))
        obj.set_linklocal_services(linklocal)

    def add(self, name, linklocal):
        update = False
        obj = self.obj_get('default-global-vrouter-config')
        if linklocal:
            self.add_linklocal(obj, linklocal)
            update = True
        if update:
            self.vnc.global_vrouter_config_update(obj)

    def delete_linklocal(self, obj, args_list):
        linklocal = obj.get_linklocal_services()
        if not linklocal:
            return
        linklocal_list = linklocal.get_linklocal_service_entry()
        for args in args_list:
            for arg in args.split(','):
                arg_name = arg.split('=')[0]
                arg_val = arg.split('=')[1]
                if (arg_name == 'name'):
                    name = arg_val
            for item in linklocal_list:
                if (item.get_linklocal_service_name() == name):
                    linklocal_list.remove(item)
                    break
        obj.set_linklocal_services(linklocal)

    def delete(self, name, linklocal):
        update = False
        obj = self.obj_get('default-global-vrouter-config')
        if linklocal:
            self.delete_linklocal(obj, linklocal)
            update = True
        if update:
            self.vnc.global_vrouter_config_update(obj)


class ConfigVrouter(ConfigObject):
    def __init__(self, client):
        super(ConfigVrouter, self).__init__(client,
                ['default-global-system-config'],
                client.vnc.virtual_router_read,
                client.vnc.virtual_routers_list)

    def show_obj(self, obj):
        print '## Virtual Router'
        print 'Name: %s' %(obj.get_fq_name())
        print 'UUID: %s' %(obj.uuid)
        print 'IP Address: %s' %(obj.get_virtual_router_ip_address())

    def add(self, name, address):
        obj = vnc_api.VirtualRouter(name = name,
                virtual_router_ip_address = address)
        try:
            self.vnc.virtual_router_create(obj)
        except Exception as e:
            print 'ERROR: %s' %(str(e))

    def delete(self, name):
        obj = self.obj_get(name, msg = True)
        if not obj:
            return
        self.vnc.virtual_router_delete(id = obj.uuid)


class ConfigImage():
    def __init__(self, client):
        self.nova = client.nova

    def obj_list(self):
        list = self.nova.images.list()
        return list

    def obj_get(self, name):
        for item in self.obj_list():
            if (item.name == name):
                return item

    def show_obj(self, obj):
        print 'Image'
        print 'Name: %s' %(obj.name)
        print 'UUID: %s' %(obj.id)

    def show(self, name = None):
        if name:
            obj = self.obj_get(name)
            if not obj:
                print 'ERROR: Object %s is not found!' %(name)
                return
            self.show_obj(obj)
        else:
            for item in self.obj_list():
                print '    %s' %(item.name)

    def add(self, name):
        pass
    def delete(self, name):
        pass


class ConfigFlavor():
    def __init__(self, client):
        self.nova = client.nova

    def obj_list(self):
        list = self.nova.flavors.list()
        return list

    def obj_get(self, name):
        for item in self.obj_list():
            if (item.name == name):
                return item

    def show_obj(self, obj):
        print 'Flavor'
        print 'Name: %s' %(obj.name)
        print 'UUID: %s' %(obj.id)

    def show(self, name = None):
        if name:
            obj = self.obj_get(name)
            if not obj:
                print 'ERROR: Object %s is not found!' %(name)
                return
            self.show_obj(obj)
        else:
            for item in self.obj_list():
                print '    %s' %(item.name)

    def add(self, name):
        pass
    def delete(self, name):
        pass


class ConfigVirtualMachine():
    def __init__(self, client):
        self.vnc = client.vnc
        self.nova = client.nova
        self.tenant = client.tenant

    def obj_list(self):
        list = self.nova.servers.list()
        return list

    def obj_get(self, name):
        for item in self.obj_list():
            if (item.name == name):
                return item

    def show_obj(self, obj):
        print 'Virtual Machine'
        print 'Name: %s' %(obj.name)
        print 'UUID: %s' %(obj.id)
        print 'Status: %s' %(obj.status)
        print 'Addresses:'
        for item in obj.addresses.keys():
            print '    %s  %s' %(obj.addresses[item][0]['addr'], item)

    def show(self, name):
        if name:
            obj = self.obj_get(name)
            if not obj:
                print 'ERROR: Object %s is not found!' %(name)
                return
            self.show_obj(obj)
        else:
            for item in self.obj_list():
                print '    %s' %(item.name)

    def add(self, name, image, flavor, network, node = None, user_data = None,
            wait = None):
        try:
            image_obj = self.nova.images.find(name = image)
        except Exception as e:
            print 'ERROR: %s' %(str(e))
            return
        try:
            flavor_obj = self.nova.flavors.find(name = flavor)
        except Exception as e:
            print 'ERROR: %s' %(str(e))
            return

        networks = []
        net_list = self.vnc.virtual_networks_list()['virtual-networks']
        for item in network:
            for vn in net_list:
                if (vn['fq_name'][1] == self.tenant.name) and \
                        (vn['fq_name'][2] == item):
                    networks.append({'net-id': vn['uuid']})
                    break
            else:
                print 'ERROR: Network %s is not found!' %(item)
                return

        #if node:
        #    zone = self.nova.availability_zones.list()[1]
        #    for item in zone.hosts.keys():
        #        if (item == node):
        #            break
        #    else:
        #        print 'ERROR: Node %s is not found!' %(name)
        #        return

        try:
            vm = self.nova.servers.create(name = name, image = image_obj,
                    flavor = flavor_obj, availability_zone = node,
                    nics = networks, userdata = user_data)
        except Exception as e:
            print 'ERROR: %s' %(str(e))
            return

        if wait:
            timeout = 12
            while timeout:
                time.sleep(3)
                vm = self.nova.servers.get(vm.id)
                if vm.status != 'BUILD':
                    print 'VM %s is %s' %(vm.name, vm.status)
                    break
                timeout -= 1

    def delete(self, name):
        obj = self.obj_get(name)
        if not obj:
            print 'ERROR: Object %s is not found!' %(name)
        self.nova.servers.delete(obj.id)


class ConfigClient():
    def __init__(self, auth_username, auth_password, auth_tenant, api_server,
            region, auth_server, tenant):
        self.vnc = vnc_api.VncApi(username = auth_username,
                password = auth_password, tenant_name = auth_tenant,
                api_server_host = api_server, auth_host = auth_server)
        self.nova = None
        if config_nova:
            self.nova = novaclient.v1_1.client.Client(username = auth_username,
                    api_key = auth_password, project_id = auth_tenant,
                    region_name = region,
                    auth_url = 'http://%s:35357/v2.0' %(auth_server))
        if not tenant:
            tenant = auth_tenant
        try:
            self.tenant = self.vnc.project_read(
                    fq_name = ['default-domain', tenant])
        except:
            self.tenant = None

