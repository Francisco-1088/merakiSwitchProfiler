import time
import config
import pandas as pd
from tabulate import tabulate

def switch_qos(dashboard, temp_src_qos, dst_net_qos, dst_net_qos_order, dst_net_id, dst_org_id):
    """
    Applies QoS rules from source template to destination network
    :param dashboard: Dashboard API client instance
    :param temp_src_qos: QoS config in source template
    :param dst_net_qos: QoS config in target network
    :param dst_net_qos_order: Order of QoS rules in destination network
    :param dst_net_id: ID of destination network
    :param dst_org_id: ID of destination organization
    :return:
    """
    src_qos = [rule for rule in temp_src_qos]
    dst_qos = [rule for rule in dst_net_qos]
    dst_qos_order = {k: dst_net_qos_order[k] for k in dst_net_qos_order.keys()}
    actions = []
    if config.supervised == True:
        print(f"Script will delete the following QoS Rules in Network {dst_net_id}:")
        print(tabulate(pd.DataFrame(dst_qos), headers='keys', tablefmt='fancy_grid'))
        print("And create the following QoS Rules:")
        print(tabulate(pd.DataFrame(src_qos), headers='keys', tablefmt='fancy_grid'))
        proceed = input("Do you wish to proceed? (Y/N): ")
        if proceed=='Y':
            # Delete all QoS rules in target template
            for item in dst_qos_order['ruleIds']:
                a = {
                    "resource": f"/networks/{dst_net_id}/switch/qosRules/{item}",
                    "operation": "destroy",
                    "body": {}
                }
                actions.append(a)
            # Create new QoS rules in target template matching source template
            for item in src_qos:
                # Remove source port and destination port from payload if set to None/Any
                # Handle exception where source/destination is a range, not individual port
                try:
                    if item['srcPort'] == None:
                        del item['srcPort']
                except KeyError:
                    pass
                try:
                    if item['dstPort'] == None:
                        del item['dstPort']
                except KeyError:
                    pass
                a = {
                    "resource": f"/networks/{dst_net_id}/switch/qosRules",
                    "operation": "create",
                    "body": {
                        **item
                    }
                }
                actions.append(a)

            # Split actions in chunks of 20 to send synchronous batches and keep QoS Rule order
            batches = [actions[x:x + 20] for x in range(0, len(actions), 20)]

            # Create one synchronous action batch for every batch in batches
            for batch in batches:
                # Check for unfinished batches
                i = False
                while not i:
                    print("Checking for unfinished batches...")
                    pending_batches = dashboard.organizations.getOrganizationActionBatches(dst_org_id, status='pending')
                    print("Current pending batches:", pending_batches)
                    if len(pending_batches) > 4:
                        i = False
                        print(f"You have {len(pending_batches)} unfinished batches:")
                        for item in pending_batches:
                            print(item['id'])
                        print("Waiting to complete some of these before scheduling a new one!")
                        time.sleep(10)
                    elif len(pending_batches) <= 4:
                        i = True
                dashboard.organizations.createOrganizationActionBatch(organizationId=dst_org_id, actions=batch, confirmed=True,
                                                                      synchronous=True)
            print(f"QoS Configuration for Network {dst_net_id} completed successfully!")
        elif proceed=='N':
            print(f"Skipping configuration of QoS Rules for Network {dst_net_id}!")
            return
        else:
            print("Unexpected Input!")
            exit()
    else:
        # Delete all QoS rules in target template
        for item in dst_qos_order['ruleIds']:
            a = {
                "resource": f"/networks/{dst_net_id}/switch/qosRules/{item}",
                "operation": "destroy",
                "body": {}
            }
            actions.append(a)
        # Create new QoS rules in target template matching source template
        for item in src_qos:
            # Remove source port and destination port from payload if set to None/Any
            # Handle exception where source/destination is a range, not individual port
            try:
                if item['srcPort'] == None:
                    del item['srcPort']
            except KeyError:
                pass
            try:
                if item['dstPort'] == None:
                    del item['dstPort']
            except KeyError:
                pass

            a = {
                "resource": f"/networks/{dst_net_id}/switch/qosRules",
                "operation": "create",
                "body": {
                    **item
                }
            }
            actions.append(a)

        # Split actions in chunks of 20 to send synchronous batches and keep QoS Rule order
        batches = [actions[x:x + 20] for x in range(0, len(actions), 20)]

        # Create one synchronous action batch for every batch in batches
        for batch in batches:
            # Check for unfinished batches
            i = False
            while not i:
                print("Checking for unfinished batches...")
                pending_batches = dashboard.organizations.getOrganizationActionBatches(dst_org_id, status='pending')
                print("Current pending batches:", pending_batches)
                if len(pending_batches) > 4:
                    i = False
                    print(f"You have {len(pending_batches)} unfinished batches:")
                    for item in pending_batches:
                        print(item['id'])
                    print("Waiting to complete some of these before scheduling a new one!")
                    time.sleep(10)
                elif len(pending_batches) <= 4:
                    i = True
            dashboard.organizations.createOrganizationActionBatch(organizationId=dst_org_id, actions=batch,
                                                                  confirmed=True,
                                                                  synchronous=True)
        print(f"QoS Configuration for Network {dst_net_id} completed successfully!")

def group_policies(dashboard, dst_net_id, dst_org_id, create_group_policies, update_group_policies):
    """
    Updates and creates necessary group policies in destination network
    :param dashboard: Dashboard API client instance
    :param create_group_policies: Group Policies to be created
    :param update_group_policies: Group Policies to be updated
    :param dst_net_id: ID of unbound network
    :param dst_org_id: ID of organization
    :return:
    """
    net = dashboard.networks.getNetwork(networkId=dst_net_id)
    prod_types = net['productTypes']

    if config.supervised == True:
        print("Script will create the following Group Policies:")
        print(tabulate(pd.DataFrame(create_group_policies), headers='keys', tablefmt='fancy_grid'))
        print("Script will update the following Group Policies:")
        print(tabulate(pd.DataFrame(update_group_policies), headers='keys', tablefmt='fancy_grid'))
        proceed=input("Do you wish to proceed? (Y/N): ")
        if proceed=='Y':
            actions = []
            for policy in update_group_policies:
                upd = {k: policy[k] for k in policy.keys()}
                if 'appliance' not in prod_types:
                    upd.pop('contentFiltering', None)
                if 'appliance' and 'wireless' not in prod_types:
                    upd['firewallAndTrafficShaping']['l7FirewallRules']=[]
                    upd['firewallAndTrafficShaping']['trafficShapingRules']=[]
                if 'wireless' not in prod_types:
                    upd.pop('splashAuthSettings', None)
                    upd.pop('vlanTagging', None)
                    upd.pop('bonjourForwarding', None)
                upd.pop('groupPolicyId', None)
                a = {
                    "resource": f"/networks/{dst_net_id}/groupPolicies/{policy['groupPolicyId']}",
                    "operation": "update",
                    "body": {
                        **upd
                    }
                }
                actions.append(a)

            for policy in create_group_policies:
                upd = {k: policy[k] for k in policy.keys()}
                if 'appliance' not in prod_types:
                    upd.pop('contentFiltering', None)
                if 'appliance' and 'wireless' not in prod_types:
                    upd['firewallAndTrafficShaping']['l7FirewallRules']=[]
                    upd['firewallAndTrafficShaping']['trafficShapingRules']=[]
                if 'wireless' not in prod_types:
                    upd.pop('splashAuthSettings', None)
                    upd.pop('vlanTagging', None)
                    upd.pop('bonjourForwarding', None)
                upd.pop('groupPolicyId', None)
                a = {
                    "resource": f"/networks/{dst_net_id}/groupPolicies",
                    "operation": "create",
                    "body": {
                        **upd
                    }
                }
                actions.append(a)

            # Split actions in chunks of 20 to send synchronous batches and destroy existing policies before creating new ones
            batches = [actions[x:x + 20] for x in range(0, len(actions), 20)]

            # Create one synchronous action batch for every batch in batches
            for batch in batches:
                # Check for unfinished batches
                i = False
                while not i:
                    print("Checking for unfinished batches")
                    current_batches = dashboard.organizations.getOrganizationActionBatches(dst_org_id)
                    unfinished_batches = []
                    for b in current_batches:
                        if b['status']['completed'] == False and b['status']['failed'] == False:
                            unfinished_batches.append(b)

                    if len(unfinished_batches) > 4:
                        i = False
                        print(f"You have {len(unfinished_batches)} unfinished batches:")
                        for item in unfinished_batches:
                            print(item['id'])
                        print("Waiting to complete some of these before scheduling a new one!")
                        time.sleep(10)
                    elif len(unfinished_batches) <= 4:
                        i = True

                dashboard.organizations.createOrganizationActionBatch(organizationId=dst_org_id, actions=batch, confirmed=True,
                                                                      synchronous=True)
            print(f"Group Policy Configuration for Network {dst_net_id} completed successfully!")
        elif proceed=='N':
            print(f"Skipping Group Policy Configuration for Network {dst_net_id}!")
            return
        else:
            print("Unexpected Input!")
            exit()
    else:
        actions = []
        for policy in update_group_policies:
            upd = {k: policy[k] for k in policy.keys()}
            if 'appliance' not in prod_types:
                upd.pop('contentFiltering', None)
            if 'appliance' and 'wireless' not in prod_types:
                upd['firewallAndTrafficShaping']['l7FirewallRules'] = []
                upd['firewallAndTrafficShaping']['trafficShapingRules'] = []
            if 'wireless' not in prod_types:
                upd.pop('splashAuthSettings', None)
                upd.pop('vlanTagging', None)
                upd.pop('bonjourForwarding', None)
            upd.pop('groupPolicyId', None)
            a = {
                "resource": f"/networks/{dst_net_id}/groupPolicies/{policy['groupPolicyId']}",
                "operation": "update",
                "body": {
                    **upd
                }
            }
            actions.append(a)

        for policy in create_group_policies:
            upd = {k: policy[k] for k in policy.keys()}
            if 'appliance' not in prod_types:
                upd.pop('contentFiltering', None)
            if 'appliance' and 'wireless' not in prod_types:
                upd['firewallAndTrafficShaping']['l7FirewallRules'] = []
                upd['firewallAndTrafficShaping']['trafficShapingRules'] = []
            if 'wireless' not in prod_types:
                upd.pop('splashAuthSettings', None)
                upd.pop('vlanTagging', None)
                upd.pop('bonjourForwarding', None)
            upd.pop('groupPolicyId', None)
            a = {
                "resource": f"/networks/{dst_net_id}/groupPolicies",
                "operation": "create",
                "body": {
                    **upd
                }
            }
            actions.append(a)

        # Split actions in chunks of 20 to send synchronous batches and destroy existing policies before creating new ones
        batches = [actions[x:x + 20] for x in range(0, len(actions), 20)]

        # Create one synchronous action batch for every batch in batches
        for batch in batches:
            # Check for unfinished batches
            i = False
            while not i:
                print("Checking for unfinished batches")
                current_batches = dashboard.organizations.getOrganizationActionBatches(dst_org_id)
                unfinished_batches = []
                for b in current_batches:
                    if b['status']['completed'] == False and b['status']['failed'] == False:
                        unfinished_batches.append(b)

                if len(unfinished_batches) > 4:
                    i = False
                    print(f"You have {len(unfinished_batches)} unfinished batches:")
                    for item in unfinished_batches:
                        print(item['id'])
                    print("Waiting to complete some of these before scheduling a new one!")
                    time.sleep(10)
                elif len(unfinished_batches) <= 4:
                    i = True

            dashboard.organizations.createOrganizationActionBatch(organizationId=dst_org_id, actions=batch,
                                                                  confirmed=True,
                                                                  synchronous=True)
        print(f"Group Policy Configuration for Network {dst_net_id} completed successfully!")

def switch_port_schedules(dashboard, dst_net_id, create_port_schedules, update_port_schedules):
    """
    Copies port schedules from source template to target network
    :param dashboard: Dashboard API client instance
    :param dst_net_id: ID of target network
    :param create_port_schedules: Port schedules to be created in target network
    :param update_port_schedules: Port schedules to be updated in target network
    :return:
    """
    if config.supervised==True:
        print("Script will create the following Port Schedules:")
        print(tabulate(pd.DataFrame(create_port_schedules), headers='keys', tablefmt='fancy_grid'))
        print("Script will update the following Port Schedules:")
        print(tabulate(pd.DataFrame(update_port_schedules), headers='keys', tablefmt='fancy_grid'))
        proceed = input("Do you wish to proceed? (Y/N):")
        if proceed == 'Y':
            for ps in create_port_schedules:
                upd = {k: ps[k] for k in ps.keys() - {
                    "id",
                    "networkId",
                    "name"
                }}
                dashboard.switch.createNetworkSwitchPortSchedule(networkId=dst_net_id, name=ps['name'], **upd)
            for ps in update_port_schedules:
                port_schedule_id = ps['id']
                upd = {k: ps[k] for k in ps.keys() - {
                    "id",
                    "networkId",
                    "name"
                }}
                dashboard.switch.updateNetworkSwitchPortSchedule(
                    networkId=dst_net_id,
                    portScheduleId=port_schedule_id,
                    name=ps['name'], **upd
                )
        elif proceed=='N':
            print("Skipping configuration of Port Schedules can cause conflicts with switch port configurations! Aborting Script!")
            exit()
        else:
            print("Unexpected Input!")
            exit()
    else:
        for ps in create_port_schedules:
            upd = {k: ps[k] for k in ps.keys() - {
                "id",
                "networkId",
                "name"
            }}
            dashboard.switch.createNetworkSwitchPortSchedule(networkId=dst_net_id, name=ps['name'], **upd)
        for ps in update_port_schedules:
            port_schedule_id = ps['id']
            upd = {k: ps[k] for k in ps.keys() - {
                "id",
                "networkId",
                "name"
            }}
            dashboard.switch.updateNetworkSwitchPortSchedule(
                networkId=dst_net_id,
                portScheduleId=port_schedule_id,
                name=ps['name'], **upd
            )

def switch_access_policies(dashboard, dst_net_id, create_access_policies, update_access_policies):
    """
    Copies access policies from source template to target network
    :param dashboard: Dashboard API client instance
    :param dst_net_id: ID of target network
    :param create_access_policies: Access Policies to be created in target network
    :param update_access_policies: Access Policies to be updated in target network
    :return:
    """
    if config.supervised==True:
        print("Script will create the following Access Policies:")
        print(tabulate(pd.DataFrame(create_access_policies), headers='keys', tablefmt='fancy_grid'))
        print("Script will update the following Access Policies:")
        print(tabulate(pd.DataFrame(update_access_policies), headers='keys', tablefmt='fancy_grid'))
        proceed = input("Do you wish to proceed? (Y/N):")
        if proceed == 'Y':
            for ap in create_access_policies:
                access_policy_number = ap['accessPolicyNumber']
                name = ap['name']
                radius_servers = ap['radiusServers']
                if ap['radiusTestingEnabled']==None:
                    ap['radiusTestingEnabled']=False
                if ap['radiusCoaSupportEnabled']==None:
                    ap['radiusCoaSupportEnabled']=False
                if ap['radiusAccountingEnabled']==None:
                    ap['radiusAccountingEnabled']=False
                if ap['urlRedirectWalledGardenEnabled']==None:
                    ap['urlRedirectWalledGardenEnabled']=False
                radius_testing = ap['radiusTestingEnabled']
                radius_coa_support = ap['radiusCoaSupportEnabled']
                radius_acct_enabled = ap['radiusAccountingEnabled']
                host_mode = ap['hostMode']
                url_redirect_walled_garden_enabled = ap['urlRedirectWalledGardenEnabled']
                upd = {k: ap[k] for k in ap.keys() - {
                    'accessPolicyNumber',
                    'name',
                    'radiusServers',
                    'radiusTestingEnabled',
                    'radiusCoaSupportEnabled',
                    'radiusAccountingEnabled',
                    'hostMode',
                    'urlRedirectWalledGardenEnabled'
                }}
                dashboard.switch.createNetworkSwitchAccessPolicy(
                    networkId=dst_net_id,
                    name=name,
                    radiusServers=radius_servers,
                    radiusTestingEnabled=radius_testing,
                    radiusCoaSupportEnabled=radius_coa_support,
                    radiusAccountingEnabled=radius_acct_enabled,
                    hostMode=host_mode,
                    urlRedirectWalledGardenEnabled=url_redirect_walled_garden_enabled,
                    **upd
                )

            for ap in update_access_policies:
                access_policy_number = ap['accessPolicyNumber']
                name = ap['name']
                radius_servers = ap['radiusServers']
                if ap['radiusTestingEnabled']==None:
                    ap['radiusTestingEnabled']=False
                if ap['radiusCoaSupportEnabled']==None:
                    ap['radiusCoaSupportEnabled']=False
                if ap['radiusAccountingEnabled']==None:
                    ap['radiusAccountingEnabled']=False
                if ap['urlRedirectWalledGardenEnabled']==None:
                    ap['urlRedirectWalledGardenEnabled']=False
                radius_testing = ap['radiusTestingEnabled']
                radius_coa_support = ap['radiusCoaSupportEnabled']
                radius_acct_enabled = ap['radiusAccountingEnabled']
                host_mode = ap['hostMode']
                url_redirect_walled_garden_enabled = ap['urlRedirectWalledGardenEnabled']
                upd = {k: ap[k] for k in ap.keys() - {
                    'name',
                    'accessPolicyNumber',
                    'radiusServers',
                    'radiusTestingEnabled',
                    'radiusCoaSupportEnabled',
                    'radiusAccountingEnabled',
                    'hostMode',
                    'urlRedirectWalledGardenEnabled'
                }}
                dashboard.switch.updateNetworkSwitchAccessPolicy(
                    networkId=dst_net_id,
                    accessPolicyNumber=access_policy_number,
                    name=name,
                    radiusServers=radius_servers,
                    radiusTestingEnabled=radius_testing,
                    radiusCoaSupportEnabled=radius_coa_support,
                    radiusAccountingEnabled=radius_acct_enabled,
                    hostMode=host_mode,
                    urlRedirectWalledGardenEnabled=url_redirect_walled_garden_enabled,
                    **upd
                )
        elif proceed=='N':
            print("Skipping Access Policy configurations can cause conflicts when copying switch port configurationss! Aborting Script!")
            exit()
        else:
            print("Unexpected Input!")
            exit()
    else:
        for ap in create_access_policies:
            access_policy_number = ap['accessPolicyNumber']
            name = ap['name']
            radius_servers = ap['radiusServers']
            if ap['radiusTestingEnabled'] == None:
                ap['radiusTestingEnabled'] = False
            if ap['radiusCoaSupportEnabled'] == None:
                ap['radiusCoaSupportEnabled'] = False
            if ap['radiusAccountingEnabled'] == None:
                ap['radiusAccountingEnabled'] = False
            if ap['urlRedirectWalledGardenEnabled'] == None:
                ap['urlRedirectWalledGardenEnabled'] = False
            radius_testing = ap['radiusTestingEnabled']
            radius_coa_support = ap['radiusCoaSupportEnabled']
            radius_acct_enabled = ap['radiusAccountingEnabled']
            host_mode = ap['hostMode']
            url_redirect_walled_garden_enabled = ap['urlRedirectWalledGardenEnabled']
            upd = {k: ap[k] for k in ap.keys() - {
                'accessPolicyNumber',
                'name',
                'radiusServers',
                'radiusTestingEnabled',
                'radiusCoaSupportEnabled',
                'radiusAccountingEnabled',
                'hostMode',
                'urlRedirectWalledGardenEnabled'
            }}
            dashboard.switch.createNetworkSwitchAccessPolicy(
                networkId=dst_net_id,
                name=name,
                radiusServers=radius_servers,
                radiusTestingEnabled=radius_testing,
                radiusCoaSupportEnabled=radius_coa_support,
                radiusAccountingEnabled=radius_acct_enabled,
                hostMode=host_mode,
                urlRedirectWalledGardenEnabled=url_redirect_walled_garden_enabled,
                **upd
            )

        for ap in update_access_policies:
            access_policy_number = ap['accessPolicyNumber']
            name = ap['name']
            radius_servers = ap['radiusServers']
            if ap['radiusTestingEnabled'] == None:
                ap['radiusTestingEnabled'] = False
            if ap['radiusCoaSupportEnabled'] == None:
                ap['radiusCoaSupportEnabled'] = False
            if ap['radiusAccountingEnabled'] == None:
                ap['radiusAccountingEnabled'] = False
            if ap['urlRedirectWalledGardenEnabled'] == None:
                ap['urlRedirectWalledGardenEnabled'] = False
            radius_testing = ap['radiusTestingEnabled']
            radius_coa_support = ap['radiusCoaSupportEnabled']
            radius_acct_enabled = ap['radiusAccountingEnabled']
            host_mode = ap['hostMode']
            url_redirect_walled_garden_enabled = ap['urlRedirectWalledGardenEnabled']
            upd = {k: ap[k] for k in ap.keys() - {
                'name',
                'accessPolicyNumber',
                'radiusServers',
                'radiusTestingEnabled',
                'radiusCoaSupportEnabled',
                'radiusAccountingEnabled',
                'hostMode',
                'urlRedirectWalledGardenEnabled'
            }}
            dashboard.switch.updateNetworkSwitchAccessPolicy(
                networkId=dst_net_id,
                accessPolicyNumber=access_policy_number,
                name=name,
                radiusServers=radius_servers,
                radiusTestingEnabled=radius_testing,
                radiusCoaSupportEnabled=radius_coa_support,
                radiusAccountingEnabled=radius_acct_enabled,
                hostMode=host_mode,
                urlRedirectWalledGardenEnabled=url_redirect_walled_garden_enabled,
                **upd
            )

def switch_ports(dashboard, dst_net_id, dst_org_id, switch_port_configs):
    """
    Copies switch port settings from switch profiles in source template into each of the target switches in the target
    network.
    :param dashboard: Dashboard API client instance
    :param dst_net_id: ID of unbound network
    :param dst_org_id: ID of organization
    :param switch_port_configs: list of switches to be updated along with the ports to update in each switch
    """
    port_schedules = dashboard.switch.getNetworkSwitchPortSchedules(networkId=dst_net_id)
    access_policies = dashboard.switch.getNetworkSwitchAccessPolicies(networkId=dst_net_id)
    actions = []
    for switch in switch_port_configs:
        if config.supervised == True:
            print(f"Script will apply the following port configurations to switch {switch['name']} - {switch['serial']}:")
            print(tabulate(pd.DataFrame(switch["ports"]), headers='keys', tablefmt='fancy_grid'))
            proceed = input("Do you wish to proceed? (Y/N):")
            if proceed=='Y':
                for port in switch['ports']:
                    upd = port
                    keys = [key for key in upd.keys()]
                    if 'linkNegotiationCapabilities' in keys:
                        del upd['linkNegotiationCapabilities']
                    if 'portScheduleId' in keys:
                        for schedule in port_schedules:
                            if schedule['name']==upd['portScheduleId']:
                                upd['portScheduleId']=schedule['id']
                    if port['type'] == 'access':
                        if port['accessPolicyType'] != 'Open':
                            for policy in access_policies:
                                if policy['name'] == port['accessPolicyNumber']:
                                    upd['accessPolicyNumber']=int(policy['accessPolicyNumber'])
                    action = {
                        "resource": f'/devices/{switch["serial"]}/switch/ports/{upd["portId"]}',
                        "operation": 'update',
                        "body": {k: upd[k] for k in upd.keys() - {'portId'}}
                    }
                    actions.append(action)
            elif proceed=='N':
                print(f"Skipping switch port configs for switch {switch['name']}-{switch['serial']}!")
                pass
            else:
                print("Unexpected Input!")
                exit()
        else:
            for port in switch['ports']:
                upd = port
                keys = [key for key in upd.keys()]
                if 'linkNegotiationCapabilities' in keys:
                    del upd['linkNegotiationCapabilities']
                if 'portScheduleId' in keys:
                    for schedule in port_schedules:
                        if schedule['name'] == upd['portScheduleId']:
                            upd['portScheduleId'] = schedule['id']
                if port['type'] == 'access':
                    if port['accessPolicyType'] != 'Open':
                        for policy in access_policies:
                            if policy['name'] == port['accessPolicyNumber']:
                                upd['accessPolicyNumber'] = int(policy['accessPolicyNumber'])
                action = {
                    "resource": f'/devices/{switch["serial"]}/switch/ports/{upd["portId"]}',
                    "operation": 'update',
                    "body": {k: upd[k] for k in upd.keys() - {'portId'}}
                }
                actions.append(action)
    for i in range(0, len(actions), 100):
        if i>=4:
            time.sleep(2)
        # Check for unfinished batches
        j = False
        while not j:
            print("Checking for unfinished batches...")
            pending_batches = dashboard.organizations.getOrganizationActionBatches(dst_org_id, status='pending')
            print("Current pending batches:",pending_batches)
            if len(pending_batches) > 4:
                j = False
                print(f"You have {len(pending_batches)} unfinished batches:")
                for item in pending_batches:
                    print(item['id'])
                print("Waiting to complete some of these before scheduling a new one!")
                time.sleep(10)
            elif len(pending_batches) <= 4:
                j = True
        subactions = actions[i:i + 100]
        print("Creating Switch Port Action Batch...")
        dashboard.organizations.createOrganizationActionBatch(
            organizationId=dst_org_id,
            actions=subactions,
            confirmed=True,
            synchronous=False
        )
        time.sleep(1)
    if len(actions)>=0:
        print(f"Switch port configs for network {dst_net_id} completed successfully!")

def switch_acl(dashboard, src_acl_config, dst_net_acl, dst_net_id):
    """
    Copies existing Switch ACL configs in template and copies it to target network
    :param dashboard: Dashbaard API client instance
    :param src_acl_config: ACL config in source template
    :param dst_net_acl: ACL config in target network
    :param dst_net_id: ID of target network
    :return:
    """
    if config.supervised==True:
        print("Script will replace these ACL rules:")
        print(tabulate(pd.DataFrame(dst_net_acl["rules"]), headers='keys', tablefmt='fancy_grid'))
        print("With these ACL rules:")
        print(tabulate(pd.DataFrame(src_acl_config["rules"]), headers='keys', tablefmt='fancy_grid'))
        proceed = input("Do you wish to proceed? (Y/N): ")
        if proceed == 'Y':
            src_temp_acl = {k: src_acl_config[k] for k in src_acl_config.keys()}
            # Remove default rule
            src_temp_acl['rules'].pop(-1)
            dashboard.switch.updateNetworkSwitchAccessControlLists(dst_net_id, src_temp_acl['rules'])
            print(f"Network ACL configuration completed successfully for {dst_net_id}!")
        elif proceed =='N':
            print(f"Skipping ACL configs for network {dst_net_id}!")
            return
        else:
            print("Unexpected Input!")
            exit()
    else:
        src_temp_acl = {k: src_acl_config[k] for k in src_acl_config.keys()}
        # Remove default rule
        src_temp_acl['rules'].pop(-1)
        dashboard.switch.updateNetworkSwitchAccessControlLists(dst_net_id, src_temp_acl['rules'])
        print(f"Network ACL configuration completed successfully for {dst_net_id}!")

def net_alerts(dashboard, dst_net_id, src_alerts, dst_alerts):
    """
    Copies existing alert settings in template and applies to target network
    :param dashboard: Dashboard API client instance
    :param dst_net_id: ID of target network
    :param src_alerts: List of alerts configured in source template
    :param dst_alerts: List of alerts in target network
    :return:
    """
    if config.supervised == True:
        print("Script will update the following Alert Settings:")
        print(tabulate(pd.DataFrame(dst_alerts["alerts"]), headers='keys', tablefmt='fancy_grid'))
        src_net_alerts = {k: src_alerts[k] for k in src_alerts.keys()}
        # Makes sure to only push alert settings the destination network is compatible with, ignoring any surplus alerts
        # That may exist in the source template
        for i in range(len(dst_alerts['alerts'])):
            for src_alert in src_net_alerts['alerts']:
                if dst_alerts['alerts'][i]['type'] == src_alert['type']:
                    if src_alert != dst_alerts['alerts'][i]:
                        dst_alerts['alerts'][i] = src_alert

        print("To these Alert Settings:")
        print(tabulate(pd.DataFrame(dst_alerts["alerts"]), headers='keys', tablefmt='fancy_grid'))
        proceed = input("Do you want to proceed? (Y/N): ")
        # Remove clientConnectivity alerts, as they give issues when updating
        if proceed == "Y":
            for i in range(len(dst_alerts['alerts'])):
                if dst_alerts['alerts'][i]['type'] == 'clientConnectivity':
                    p = i
                    dst_alerts['alerts'].pop(p)
            dashboard.networks.updateNetworkAlertsSettings(networkId=dst_net_id, **dst_alerts)
        elif proceed =='N':
            exit()
        else:
            exit()
    else:
        src_net_alerts = {k: src_alerts[k] for k in src_alerts.keys()}
        for i in range(len(dst_alerts['alerts'])):
            for src_alert in src_net_alerts['alerts']:
                if dst_alerts['alerts'][i]['type'] == src_alert['type']:
                    if src_alert != dst_alerts['alerts'][i]:
                        dst_alerts['alerts'][i] = src_alert
        # Remove clientConnectivity alerts, as they give issues when updating
        for i in range(len(dst_alerts['alerts'])):
            if dst_alerts['alerts'][i]['type'] == 'clientConnectivity':
                p = i
                dst_alerts['alerts'].pop(p)
        dashboard.networks.updateNetworkAlertsSettings(networkId=dst_net_id, **dst_alerts)

def net_syslog(dashboard, src_syslog, dst_syslog, dst_net_id):
    """
    Copies syslog settings in template and applies to target network
    :param dashboard: Dashboard API client instance
    :param src_syslog: List of syslog servers in source template
    :param dst_syslog: List of syslog servers in destination template
    :param dst_net_id: ID of target network
    :return:
    """
    if config.supervised == True:
        print("Script will update the following Syslog Settings:")
        print(tabulate(pd.DataFrame(dst_syslog["servers"]), headers='keys', tablefmt='fancy_grid'))
        print("To the following Syslog Settings:")
        print(tabulate(pd.DataFrame(src_syslog["servers"]), headers='keys', tablefmt='fancy_grid'))
        proceed=input("Do you want to proceed? (Y/N): ")
        if proceed=='Y':
            dashboard.networks.updateNetworkSyslogServers(networkId=dst_net_id, servers=src_syslog['servers'])
        elif proceed=='N':
            exit()
        else:
            exit()
    else:
        dashboard.networks.updateNetworkSyslogServers(networkId=dst_net_id, servers=src_syslog['servers'])

def net_snmp(dashboard, src_snmp, dst_snmp, dst_net_id):
    """
    Copies existing SNMP settings in template and applies to target network
    :param dashboard: Dashboard API client instance
    :param src_snmp: SNMP config in source template
    :param dst_snmp: SNMP config in target network
    :param dst_net_id: ID of target network
    :return:
    """
    if config.supervised == True:
        print("Script will update the following SNMP Settings:")
        print(tabulate(pd.DataFrame([dst_snmp]), headers='keys', tablefmt='fancy_grid'))
        print("To the following SNMP Settings:")
        print(tabulate(pd.DataFrame([src_snmp]), headers='keys', tablefmt='fancy_grid'))
        proceed=input("Do you want to proceed? (Y/N): ")
        if proceed=='Y':
            dashboard.networks.updateNetworkSnmp(networkId=dst_net_id, **src_snmp)
        elif proceed=='N':
            print(f"Skipping SNMP config update for network {dst_net_id}!")
            return
        else:
            print("Unexpected Input!")
            exit()
    else:
        dashboard.networks.updateNetworkSnmp(networkId=dst_net_id, **src_snmp)

def net_analytics(dashboard, src_net_analytics, dst_net_analytics, dst_net_id):
    """
    Copies existing analytics settings in template and applies to target network
    :param dashboard: Dashboard API client instance
    :param src_net_analytics: Network Analytics in source template
    :param dst_net_analytics: Network Analytics in target network
    :param dst_net_id: ID of target network
    :return:
    """
    if config.supervised == True:
        print("Script will update the Network Analytics config from this:")
        print(tabulate(pd.DataFrame([dst_net_analytics]), headers='keys', tablefmt='fancy_grid'))
        print("To this:")
        print(tabulate(pd.DataFrame([src_net_analytics]), headers='keys', tablefmt='fancy_grid'))
        proceed=input("Do you wish to proceed? (Y/N): ")
        if proceed=='Y':
            dashboard.networks.updateNetworkTrafficAnalysis(networkId=dst_net_id, **src_net_analytics)
            print(f"Network analytics configured successfully for network {dst_net_id}!")
        elif proceed=='N':
            print(f"Skipping Network Analytics configuration for network {dst_net_id}")
            return
        else:
            print("Unexpected Input!")
            exit()
    else:
        dashboard.networks.updateNetworkTrafficAnalysis(networkId=dst_net_id, **src_net_analytics)
        print(f"Network analytics configured successfully for network {dst_net_id}!")
