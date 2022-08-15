import config
import re
import read_functions
import write_functions
import asyncio
import meraki.aio

# Instantiate async Meraki API client
aiomeraki = meraki.aio.AsyncDashboardAPI(
            config.api_key,
            base_url="https://api.meraki.com/api/v1",
            log_file_prefix=__file__[:-3],
            print_console=False,)

# Instantiate synchronous Meraki API client
dashboard = meraki.DashboardAPI(
    config.api_key,
    base_url="https://api.meraki.com/api/v1",
    log_file_prefix=__file__[:-3],
    print_console=config.console_logging,
    )

if __name__ == "__main__":
    # -------------------Gather switch specific data-------------------
    loop = asyncio.get_event_loop()
    target_devices, target_networks, temp_switch_profiles, temp_switch_profile_ports_dict, \
    temp_access_policies, temp_port_schedules, net_attributes, target_switch_ports, \
    src_acl_config, src_qos_config, src_qos_order_config, src_group_policies, src_network_alerts, \
    src_syslog_config, src_snmp_config, src_net_analytics \
        = loop.run_until_complete(read_functions.main(aiomeraki))

    for key in net_attributes.keys():
        print("Working on network",key,":")

        # -------------------Copy Access Policies-------------------

        # Construct a set of the names in the template Access Policies, and another of the names in the network
        # Access Policies. Compare both sets, and determine which policies must be created and which must be updated
        template_ap_set = set(ap['name'] for ap in temp_access_policies)
        net_ap_set = set(ap['name'] for ap in net_attributes[key]['access_policies'])
        to_create = template_ap_set.difference(net_ap_set)
        to_update = template_ap_set.difference(to_create)

        # Construct a list of Access Policies to Create and Update based on the previous set operation
        create_access_policies = [ap for ap in temp_access_policies if ap['name'] in to_create]
        update_access_policies = [ap for ap in temp_access_policies if ap['name'] in to_update]
        for ap in update_access_policies:
            for apn in net_attributes[key]['access_policies']:
                if ap['name']==apn['name']:
                    ap['accessPolicyNumber']=apn['accessPolicyNumber']

        write_functions.switch_access_policies(
            dashboard=dashboard,
            dst_net_id=key,
            create_access_policies=create_access_policies,
            update_access_policies=update_access_policies
        )

        print(f"Access Policies copied to network {key} successfully.")

        # -------------------Copy Group Policies-------------------

        # Construct a set of the names in the template Group Policies, and another of the names in the network
        # Group Policies. Compare both sets, and determine which policies must be created and which must be updated
        template_gp_set = set(gp['name'] for gp in src_group_policies)
        net_gp_set = set(gp['name'] for gp in net_attributes[key]['group_policies'])
        to_create = template_gp_set.difference(net_gp_set)
        to_update = template_gp_set.difference(to_create)

        # Construct a list of Group Policies to Create and Update based on the previous set operation
        create_group_policies = [gp for gp in src_group_policies if gp['name'] in to_create]
        update_group_policies = [gp for gp in src_group_policies if gp['name'] in to_update]

        for gp in update_group_policies:
            for gpn in net_attributes[key]['group_policies']:
                if gp['name']==gpn['name']:
                    gp['groupPolicyId']=gpn['groupPolicyId']

        write_functions.group_policies(
            dashboard=dashboard,
            dst_net_id=key,
            dst_org_id=config.dst_org_id,
            create_group_policies=create_group_policies,
            update_group_policies=update_group_policies
        )

        # -------------------Copy Net Alerts-------------------
        write_functions.net_alerts(
            dashboard=dashboard,
            dst_net_id=key,
            src_alerts=src_network_alerts,
            dst_alerts=net_attributes[key]['net_alerts']
        )

        # -------------------Copy ACL-------------------
        write_functions.switch_acl(
            dashboard=dashboard,
            src_acl_config=src_acl_config,
            dst_net_acl=net_attributes[key]['acl'],
            dst_net_id=key
        )

        # -------------------Copy QOS-------------------
        write_functions.switch_qos(
            dashboard=dashboard,
            temp_src_qos=src_qos_config,
            dst_net_qos=net_attributes[key]["qos_rules"],
            dst_net_qos_order=net_attributes[key]["qos_rules_order"],
            dst_net_id=key,
            dst_org_id=config.dst_org_id
        )

        # -------------------Copy SNMP-------------------
        write_functions.net_snmp(
            dashboard=dashboard,
            src_snmp=src_snmp_config,
            dst_snmp=net_attributes[key]["snmp"],
            dst_net_id=key
        )

        # -------------------Copy Syslog-------------------
        write_functions.net_syslog(
            dashboard=dashboard,
            src_syslog=src_syslog_config,
            dst_syslog=net_attributes[key]["syslog"],
            dst_net_id=key
        )

        # Copy Net Analytics
        write_functions.net_analytics(
            dashboard=dashboard,
            src_net_analytics=src_net_analytics,
            dst_net_analytics=net_attributes[key]['net_analytics'],
            dst_net_id=key
        )

        # -------------------Copy Port Schedules-------------------

        # Construct a set of the names in the template Port Schedules, and another of the names in the network
        # Port Schedules. Compare both sets, and determine which schedules must be created and which must be updated
        template_ps_set = set(ap['name'] for ap in temp_port_schedules)
        net_ps_set = set(ap['name'] for ap in net_attributes[key]['port_schedules'])
        to_create = template_ps_set.difference(net_ps_set)
        to_update = template_ps_set.difference(to_create)

        # Construct list of port schedules to be created and updated based on the result of the previous set operation
        create_port_schedules = [ps for ps in temp_port_schedules if ps['name'] in to_create]
        update_port_schedules = [ps for ps in temp_port_schedules if ps['name'] in to_update]
        for ps in update_port_schedules:
            for psn in net_attributes[key]['port_schedules']:
                if ps['name']==psn['name']:
                    ps['id']=psn['id']

        write_functions.switch_port_schedules(
            dashboard=dashboard,
            dst_net_id=key,
            create_port_schedules=create_port_schedules,
            update_port_schedules=update_port_schedules
        )

        print(f"Port schedules copied to network {key} successfully.")

        # -------------------Copy Switch Ports-------------------

        # Add tags to list of switches to operate on for simplicity
        for switch_x in target_switch_ports:
            for switch_y in target_devices:
                if switch_x['serial']==switch_y['serial']:
                    switch_x['tags']=switch_y['tags']

        # Filter list of switches with the current network key
        net_target_switch_ports = [switch for switch in target_switch_ports if switch['network']['id']==key]
        pop = []
        for i in range(len(net_target_switch_ports)):
            for k in temp_switch_profile_ports_dict.keys():
                if k in net_target_switch_ports[i]['tags']:
                    # Compare Model in Switch Profile with Model in Switch to Update
                    # If unequal, skip that switch
                    if re.sub("[FPUXL]","",net_target_switch_ports[i]['model'])==re.sub("[FPUXL]","",temp_switch_profile_ports_dict[k]['model']):
                        # Find ports with the ignore_port_tag from the config file in the destination switch
                        # If any such ports are found, don't update those ports
                        ignore_ports = [port["portId"] for port in net_target_switch_ports[i]["ports"] if config.ignore_port_tag in port['tags']]
                        net_target_switch_ports[i]['ports']=[switchport for switchport in temp_switch_profile_ports_dict[k]['ports'] if switchport["portId"] not in ignore_ports]
                    else:
                        print(f"Switch {net_target_switch_ports[i]['name']} does not match profile {k}'s model.")
                        pop.append(i)
        # Skip switches found to not match model to their assigned profile
        for i in reversed(pop):
            net_target_switch_ports.pop(i)

        write_functions.switch_ports(
            dashboard=dashboard,
            dst_net_id=key,
            dst_org_id=config.dst_org_id,
            switch_port_configs=net_target_switch_ports
        )



