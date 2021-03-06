res_identifier = {u'access-control-list': {'class-name': u'AccessControlList',
                          'name': u'access-control-list',
                          'parent': [u'virtual-network', u'security-group'],
                          'property': {u'access-control-list-entries': {'type': u'AclEntriesType'},
                                       u'display-name': {'type': u'xsd:string'},
                                       u'id-perms': {'type': u'IdPermsType'}},
                          'reference': {}},
 u'analytics-node': {'class-name': u'AnalyticsNode',
                     'name': u'analytics-node',
                     'parent': [u'global-system-config'],
                     'property': {u'analytics-node-ip-address': {'type': u'IpAddressType'},
                                  u'display-name': {'type': u'xsd:string'},
                                  u'id-perms': {'type': u'IdPermsType'}},
                     'reference': {}},
 'bgp-router': {'class-name': 'BgpRouter',
                'name': 'bgp-router',
                'parent': None,
                'property': {u'display-name': {'type': u'xsd:string'},
                             u'id-perms': {'type': u'IdPermsType'}},
                'reference': {}},
 u'config-node': {'class-name': u'ConfigNode',
                  'name': u'config-node',
                  'parent': [u'global-system-config'],
                  'property': {u'config-node-ip-address': {'type': u'IpAddressType'},
                               u'display-name': {'type': u'xsd:string'},
                               u'id-perms': {'type': u'IdPermsType'}},
                  'reference': {}},
 u'config-root': {'class-name': u'ConfigRoot',
                  'name': u'config-root',
                  'parent': None,
                  'property': {u'api-access-list': {'type': u'ApiAccessListType'},
                               u'display-name': {'type': u'xsd:string'},
                               u'id-perms': {'type': u'IdPermsType'}},
                  'reference': {}},
 'customer-attachment': {'class-name': 'CustomerAttachment',
                         'name': 'customer-attachment',
                         'parent': None,
                         'property': {u'display-name': {'type': u'xsd:string'},
                                      u'id-perms': {'type': u'IdPermsType'}},
                         'reference': {u'floating-ip': {'attr': None},
                                       'virtual-machine-interface': {'attr': None}}},
 u'database-node': {'class-name': u'DatabaseNode',
                    'name': u'database-node',
                    'parent': [u'global-system-config'],
                    'property': {u'database-node-ip-address': {'type': u'IpAddressType'},
                                 u'display-name': {'type': u'xsd:string'},
                                 u'id-perms': {'type': u'IdPermsType'}},
                    'reference': {}},
 u'domain': {'class-name': u'Domain',
             'name': u'domain',
             'parent': [u'config-root'],
             'property': {u'api-access-list': {'type': u'ApiAccessListType'},
                          u'display-name': {'type': u'xsd:string'},
                          u'domain-limits': {'type': u'DomainLimitsType'},
                          u'id-perms': {'type': u'IdPermsType'}},
             'reference': {}},
 u'floating-ip': {'class-name': u'FloatingIp',
                  'name': u'floating-ip',
                  'parent': [u'floating-ip-pool'],
                  'property': {u'display-name': {'type': u'xsd:string'},
                               u'floating-ip-address': {'type': u'IpAddressType'},
                               u'floating-ip-address-family': {'type': u'IpAddressFamilyType'},
                               u'floating-ip-fixed-ip-address': {'type': u'IpAddressType'},
                               u'floating-ip-is-virtual-ip': {'type': u'xsd:boolean'},
                               u'id-perms': {'type': u'IdPermsType'}},
                  'reference': {u'project': {'attr': None},
                                'virtual-machine-interface': {'attr': None}}},
 u'floating-ip-pool': {'class-name': u'FloatingIpPool',
                       'name': u'floating-ip-pool',
                       'parent': [u'virtual-network'],
                       'property': {u'display-name': {'type': u'xsd:string'},
                                    u'floating-ip-pool-prefixes': {'type': u'FloatingIpPoolType'},
                                    u'id-perms': {'type': u'IdPermsType'}},
                       'reference': {}},
 u'global-system-config': {'class-name': u'GlobalSystemConfig',
                           'name': u'global-system-config',
                           'parent': [u'config-root'],
                           'property': {u'autonomous-system': {'type': u'AutonomousSystemType'},
                                        u'config-version': {'type': u'xsd:string'},
                                        u'display-name': {'type': u'xsd:string'},
                                        u'ibgp-auto-mesh': {'type': u'xsd:boolean'},
                                        u'id-perms': {'type': u'IdPermsType'},
                                        u'ip-fabric-subnets': {'type': u'SubnetListType'},
                                        u'plugin-tuning': {'type': u'PluginProperties'}},
                           'reference': {'bgp-router': {'attr': None}}},
 u'global-vrouter-config': {'class-name': u'GlobalVrouterConfig',
                            'name': u'global-vrouter-config',
                            'parent': [u'global-system-config'],
                            'property': {u'display-name': {'type': u'xsd:string'},
                                         u'encapsulation-priorities': {'type': u'EncapsulationPrioritiesType'},
                                         u'forwarding-mode': {'type': u'ForwardingModeType'},
                                         u'id-perms': {'type': u'IdPermsType'},
                                         u'linklocal-services': {'type': u'LinklocalServicesTypes'},
                                         u'vxlan-network-identifier-mode': {'type': u'VxlanNetworkIdentifierModeType'}},
                            'reference': {}},
 u'instance-ip': {'class-name': u'InstanceIp',
                  'name': u'instance-ip',
                  'parent': None,
                  'property': {u'display-name': {'type': u'xsd:string'},
                               u'id-perms': {'type': u'IdPermsType'},
                               u'instance-ip-address': {'type': u'IpAddressType'},
                               u'instance-ip-family': {'type': u'IpAddressFamilyType'},
                               u'instance-ip-mode': {'type': u'AddressMode'},
                               u'instance-ip-secondary': {'type': u'xsd:boolean'},
                               u'subnet-uuid': {'type': u'xsd:string'}},
                  'reference': {'physical-router': {'attr': None},
                                'virtual-machine-interface': {'attr': None},
                                u'virtual-network': {'attr': None}}},
 u'interface-route-table': {'class-name': u'InterfaceRouteTable',
                            'name': u'interface-route-table',
                            'parent': [u'project'],
                            'property': {u'display-name': {'type': u'xsd:string'},
                                         u'id-perms': {'type': u'IdPermsType'},
                                         u'interface-route-table-routes': {'type': u'RouteTableType'}},
                            'reference': {}},
 'loadbalancer': {'class-name': 'Loadbalancer',
                  'name': 'loadbalancer',
                  'parent': [u'project'],
                  'property': {u'display-name': {'type': u'xsd:string'},
                               u'id-perms': {'type': u'IdPermsType'},
                               u'loadbalancer-properties': {'type': u'LoadbalancerType'}},
                  'reference': {'virtual-machine-interface': {'attr': None}}},
 u'loadbalancer-healthmonitor': {'class-name': u'LoadbalancerHealthmonitor',
                                 'name': u'loadbalancer-healthmonitor',
                                 'parent': [u'project'],
                                 'property': {u'display-name': {'type': u'xsd:string'},
                                              u'id-perms': {'type': u'IdPermsType'},
                                              u'loadbalancer-healthmonitor-properties': {'type': u'LoadbalancerHealthmonitorType'}},
                                 'reference': {}},
 'loadbalancer-listener': {'class-name': 'LoadbalancerListener',
                           'name': 'loadbalancer-listener',
                           'parent': [u'project'],
                           'property': {u'display-name': {'type': u'xsd:string'},
                                        u'id-perms': {'type': u'IdPermsType'},
                                        u'loadbalancer-listener-properties': {'type': u'LoadbalancerListenerType'}},
                           'reference': {'loadbalancer': {'attr': None}}},
 u'loadbalancer-member': {'class-name': u'LoadbalancerMember',
                          'name': u'loadbalancer-member',
                          'parent': [u'loadbalancer-pool'],
                          'property': {u'display-name': {'type': u'xsd:string'},
                                       u'id-perms': {'type': u'IdPermsType'},
                                       u'loadbalancer-member-properties': {'type': u'LoadbalancerMemberType'}},
                          'reference': {}},
 u'loadbalancer-pool': {'class-name': u'LoadbalancerPool',
                        'name': u'loadbalancer-pool',
                        'parent': [u'project'],
                        'property': {u'display-name': {'type': u'xsd:string'},
                                     u'id-perms': {'type': u'IdPermsType'},
                                     u'loadbalancer-pool-custom-attributes': {'type': u'KeyValuePairs'},
                                     u'loadbalancer-pool-properties': {'type': u'LoadbalancerPoolType'},
                                     u'loadbalancer-pool-provider': {'type': u'xsd:string'}},
                        'reference': {u'loadbalancer-healthmonitor': {'attr': None},
                                      'loadbalancer-listener': {'attr': None},
                                      u'service-appliance-set': {'attr': None},
                                      u'service-instance': {'attr': None},
                                      'virtual-machine-interface': {'attr': None}}},
 u'logical-interface': {'class-name': u'LogicalInterface',
                        'name': u'logical-interface',
                        'parent': ['physical-router', u'physical-interface'],
                        'property': {u'display-name': {'type': u'xsd:string'},
                                     u'id-perms': {'type': u'IdPermsType'},
                                     u'logical-interface-type': {'type': u'LogicalInterfaceType'},
                                     u'logical-interface-vlan-tag': {'type': u'xsd:integer'}},
                        'reference': {'virtual-machine-interface': {'attr': None}}},
 'logical-router': {'class-name': 'LogicalRouter',
                    'name': 'logical-router',
                    'parent': [u'project'],
                    'property': {u'configured-route-target-list': {'type': u'RouteTargetList'},
                                 u'display-name': {'type': u'xsd:string'},
                                 u'id-perms': {'type': u'IdPermsType'}},
                    'reference': {'route-target': {'attr': None},
                                  u'service-instance': {'attr': None},
                                  'virtual-machine-interface': {'attr': None},
                                  u'virtual-network': {'attr': None}}},
 u'namespace': {'class-name': u'Namespace',
                'name': u'namespace',
                'parent': [u'domain'],
                'property': {u'display-name': {'type': u'xsd:string'},
                             u'id-perms': {'type': u'IdPermsType'},
                             u'namespace-cidr': {'type': u'SubnetType'}},
                'reference': {}},
 u'network-ipam': {'class-name': u'NetworkIpam',
                   'name': u'network-ipam',
                   'parent': [u'project'],
                   'property': {u'display-name': {'type': u'xsd:string'},
                                u'id-perms': {'type': u'IdPermsType'},
                                u'network-ipam-mgmt': {'type': u'IpamType'}},
                   'reference': {u'virtual-DNS': {'attr': None}}},
 u'network-policy': {'class-name': u'NetworkPolicy',
                     'name': u'network-policy',
                     'parent': [u'project'],
                     'property': {u'display-name': {'type': u'xsd:string'},
                                  u'id-perms': {'type': u'IdPermsType'},
                                  u'network-policy-entries': {'type': u'PolicyEntriesType'}},
                     'reference': {}},
 u'physical-interface': {'class-name': u'PhysicalInterface',
                         'name': u'physical-interface',
                         'parent': ['physical-router'],
                         'property': {u'display-name': {'type': u'xsd:string'},
                                      u'id-perms': {'type': u'IdPermsType'}},
                         'reference': {u'physical-interface': {'attr': None}}},
 'physical-router': {'class-name': 'PhysicalRouter',
                     'name': 'physical-router',
                     'parent': [u'global-system-config'],
                     'property': {u'display-name': {'type': u'xsd:string'},
                                  u'id-perms': {'type': u'IdPermsType'},
                                  u'physical-router-dataplane-ip': {'type': u'IpAddress'},
                                  u'physical-router-junos-service-ports': {'type': u'JunosServicePorts'},
                                  u'physical-router-management-ip': {'type': u'IpAddress'},
                                  u'physical-router-product-name': {'type': u'xsd:string'},
                                  u'physical-router-snmp-credentials': {'type': u'SNMPCredentials'},
                                  u'physical-router-user-credentials': {'type': u'UserCredentials'},
                                  u'physical-router-vendor-name': {'type': u'xsd:string'},
                                  u'physical-router-vnc-managed': {'type': u'xsd:boolean'}},
                     'reference': {'bgp-router': {'attr': None},
                                   u'virtual-network': {'attr': None},
                                   'virtual-router': {'attr': None}}},
 u'project': {'class-name': u'Project',
              'name': u'project',
              'parent': [u'domain'],
              'property': {u'display-name': {'type': u'xsd:string'},
                           u'id-perms': {'type': u'IdPermsType'},
                           u'quota': {'type': u'QuotaType'}},
              'reference': {u'floating-ip-pool': {'attr': None},
                            u'namespace': {'attr': u'SubnetType'}}},
 'provider-attachment': {'class-name': 'ProviderAttachment',
                         'name': 'provider-attachment',
                         'parent': None,
                         'property': {u'display-name': {'type': u'xsd:string'},
                                      u'id-perms': {'type': u'IdPermsType'}},
                         'reference': {'virtual-router': {'attr': None}}},
 u'qos-forwarding-class': {'class-name': u'QosForwardingClass',
                           'name': u'qos-forwarding-class',
                           'parent': [u'project'],
                           'property': {u'display-name': {'type': u'xsd:string'},
                                        u'dscp': {'type': u'xsd:integer'},
                                        u'id-perms': {'type': u'IdPermsType'},
                                        u'trusted': {'type': u'xsd:boolean'}},
                           'reference': {u'qos-queue': {'attr': None}}},
 u'qos-queue': {'class-name': u'QosQueue',
                'name': u'qos-queue',
                'parent': [u'project'],
                'property': {u'display-name': {'type': u'xsd:string'},
                             u'id-perms': {'type': u'IdPermsType'},
                             u'max-bandwidth': {'type': u'xsd:integer'},
                             u'min-bandwidth': {'type': u'xsd:integer'}},
                'reference': {}},
 u'route-table': {'class-name': u'RouteTable',
                  'name': u'route-table',
                  'parent': [u'project'],
                  'property': {u'display-name': {'type': u'xsd:string'},
                               u'id-perms': {'type': u'IdPermsType'},
                               u'routes': {'type': u'RouteTableType'}},
                  'reference': {}},
 'route-target': {'class-name': 'RouteTarget',
                  'name': 'route-target',
                  'parent': None,
                  'property': {u'display-name': {'type': u'xsd:string'},
                               u'id-perms': {'type': u'IdPermsType'}},
                  'reference': {}},
 'routing-instance': {'class-name': 'RoutingInstance',
                      'name': 'routing-instance',
                      'parent': [u'virtual-network'],
                      'property': {u'display-name': {'type': u'xsd:string'},
                                   u'id-perms': {'type': u'IdPermsType'}},
                      'reference': {}},
 u'security-group': {'class-name': u'SecurityGroup',
                     'name': u'security-group',
                     'parent': [u'project'],
                     'property': {u'configured-security-group-id': {'type': u'xsd:integer'},
                                  u'display-name': {'type': u'xsd:string'},
                                  u'id-perms': {'type': u'IdPermsType'},
                                  u'security-group-entries': {'type': u'PolicyEntriesType'},
                                  u'security-group-id': {'type': u'xsd:string'}},
                     'reference': {}},
 u'service-appliance': {'class-name': u'ServiceAppliance',
                        'name': u'service-appliance',
                        'parent': [u'service-appliance-set'],
                        'property': {u'display-name': {'type': u'xsd:string'},
                                     u'id-perms': {'type': u'IdPermsType'},
                                     u'service-appliance-ip-address': {'type': u'IpAddressType'},
                                     u'service-appliance-properties': {'type': u'KeyValuePairs'},
                                     u'service-appliance-user-credentials': {'type': u'UserCredentials'}},
                        'reference': {u'physical-interface': {'attr': u'ServiceApplianceInterfaceType'}}},
 u'service-appliance-set': {'class-name': u'ServiceApplianceSet',
                            'name': u'service-appliance-set',
                            'parent': [u'global-system-config'],
                            'property': {u'display-name': {'type': u'xsd:string'},
                                         u'id-perms': {'type': u'IdPermsType'},
                                         u'service-appliance-driver': {'type': u'xsd:string'},
                                         u'service-appliance-ha-mode': {'type': u'xsd:string'},
                                         u'service-appliance-set-properties': {'type': u'KeyValuePairs'}},
                            'reference': {}},
 u'service-instance': {'class-name': u'ServiceInstance',
                       'name': u'service-instance',
                       'parent': [u'project'],
                       'property': {u'display-name': {'type': u'xsd:string'},
                                    u'id-perms': {'type': u'IdPermsType'},
                                    u'service-instance-properties': {'type': u'ServiceInstanceType'}},
                       'reference': {'service-template': {'attr': None},
                                     'virtual-machine-interface': {'attr': u'ServiceInstanceVirtualMachineInterfaceType'}}},
 'service-template': {'class-name': 'ServiceTemplate',
                      'name': 'service-template',
                      'parent': [u'domain'],
                      'property': {u'display-name': {'type': u'xsd:string'},
                                   u'id-perms': {'type': u'IdPermsType'},
                                   u'service-template-properties': {'type': u'ServiceTemplateType'}},
                      'reference': {u'service-appliance-set': {'attr': None}}},
 u'subnet': {'class-name': u'Subnet',
             'name': u'subnet',
             'parent': None,
             'property': {u'display-name': {'type': u'xsd:string'},
                          u'id-perms': {'type': u'IdPermsType'},
                          u'subnet-ip-prefix': {'type': u'SubnetType'}},
             'reference': {'virtual-machine-interface': {'attr': None}}},
 u'virtual-DNS': {'class-name': u'VirtualDns',
                  'name': u'virtual-DNS',
                  'parent': [u'domain'],
                  'property': {u'display-name': {'type': u'xsd:string'},
                               u'id-perms': {'type': u'IdPermsType'},
                               u'virtual-DNS-data': {'type': u'VirtualDnsType'}},
                  'reference': {}},
 u'virtual-DNS-record': {'class-name': u'VirtualDnsRecord',
                         'name': u'virtual-DNS-record',
                         'parent': [u'virtual-DNS'],
                         'property': {u'display-name': {'type': u'xsd:string'},
                                      u'id-perms': {'type': u'IdPermsType'},
                                      u'virtual-DNS-record-data': {'type': u'VirtualDnsRecordType'}},
                         'reference': {}},
 u'virtual-ip': {'class-name': u'VirtualIp',
                 'name': u'virtual-ip',
                 'parent': [u'project'],
                 'property': {u'display-name': {'type': u'xsd:string'},
                              u'id-perms': {'type': u'IdPermsType'},
                              u'virtual-ip-properties': {'type': u'VirtualIpType'}},
                 'reference': {u'loadbalancer-pool': {'attr': None},
                               'virtual-machine-interface': {'attr': None}}},
 u'virtual-machine': {'class-name': u'VirtualMachine',
                      'name': u'virtual-machine',
                      'parent': None,
                      'property': {u'display-name': {'type': u'xsd:string'},
                                   u'id-perms': {'type': u'IdPermsType'}},
                      'reference': {u'service-instance': {'attr': None}}},
 'virtual-machine-interface': {'class-name': 'VirtualMachineInterface',
                               'name': 'virtual-machine-interface',
                               'parent': [u'virtual-machine', u'project'],
                               'property': {u'display-name': {'type': u'xsd:string'},
                                            u'id-perms': {'type': u'IdPermsType'},
                                            u'virtual-machine-interface-allowed-address-pairs': {'type': u'AllowedAddressPairs'},
                                            u'virtual-machine-interface-device-owner': {'type': u'xsd:string'},
                                            u'virtual-machine-interface-dhcp-option-list': {'type': u'DhcpOptionsListType'},
                                            u'virtual-machine-interface-host-routes': {'type': u'RouteTableType'},
                                            u'virtual-machine-interface-mac-addresses': {'type': u'MacAddressesType'},
                                            u'virtual-machine-interface-properties': {'type': u'VirtualMachineInterfacePropertiesType'},
                                            u'vrf-assign-table': {'type': u'VrfAssignTableType'}},
                               'reference': {u'interface-route-table': {'attr': None},
                                             u'physical-interface': {'attr': None},
                                             u'qos-forwarding-class': {'attr': None},
                                             'routing-instance': {'attr': u'PolicyBasedForwardingRuleType'},
                                             u'security-group': {'attr': None},
                                             u'virtual-machine': {'attr': None},
                                             'virtual-machine-interface': {'attr': None},
                                             u'virtual-network': {'attr': None}}},
 u'virtual-network': {'class-name': u'VirtualNetwork',
                      'name': u'virtual-network',
                      'parent': [u'project'],
                      'property': {u'display-name': {'type': u'xsd:string'},
                                   u'external-ipam': {'type': u'xsd:boolean'},
                                   u'flood-unknown-unicast': {'type': u'xsd:boolean'},
                                   u'id-perms': {'type': u'IdPermsType'},
                                   u'is-shared': {'type': u'xsd:boolean'},
                                   u'route-target-list': {'type': u'RouteTargetList'},
                                   u'router-external': {'type': u'xsd:boolean'},
                                   u'virtual-network-network-id': {'type': u'xsd:integer'},
                                   u'virtual-network-properties': {'type': u'VirtualNetworkType'}},
                      'reference': {u'network-ipam': {'attr': u'VnSubnetsType'},
                                    u'network-policy': {'attr': u'VirtualNetworkPolicyType'},
                                    u'qos-forwarding-class': {'attr': None},
                                    u'route-table': {'attr': None}}},
 'virtual-router': {'class-name': 'VirtualRouter',
                    'name': 'virtual-router',
                    'parent': [u'global-system-config'],
                    'property': {u'display-name': {'type': u'xsd:string'},
                                 u'id-perms': {'type': u'IdPermsType'},
                                 u'virtual-router-ip-address': {'type': u'IpAddressType'},
                                 u'virtual-router-type': {'type': u'VirtualRouterType'}},
                    'reference': {'bgp-router': {'attr': None},
                                  u'virtual-machine': {'attr': None}}}}
