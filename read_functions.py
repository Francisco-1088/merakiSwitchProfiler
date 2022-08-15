import config
import pandas as pd
from tabulate import tabulate

async def gather_switch_specific_data(aiomeraki):
    """
    Gathers the information necessary to propagate switch configs from the source template specified in the config.py
    file.
    :param aiomeraki: asyncio instance of the Dashboard API client with access to the source and target organizations,
    as well as the source configuration templates
    :returns: target_devices: List of dicts containing each of the switches to be updated across the whole organization.
             target_networks: List of dicts containing each of the networks with switches to be updated across the
             whole organization.
             temp_switch_profiles: List of dicts containing each of the switch profiles in the source configuration
             template.
             temp_switch_profile_ports: List of dicts with each of the existing ports in the switch profile in the
             source configuration template.
             temp_access_policies: List of dicts with each of the access policies existing in the source configuration
             template.
             temp_port_schedules: List of dicts with each of the port schedules existing in the source configuration
             template.
             net_attributes: Dict containing a Key for every Network to be updated including their existing Access
             Policies and Port Schedules.
             target_switch_ports: List of dicts containing each of the switches to be updated along with the ports to
             update in each one.
    """
    # Get list of MS devices in the organization with the tag specified in config.dst_switch_tag
    org_devices = await aiomeraki.organizations.getOrganizationDevices(
        organizationId=config.src_org_id,
        tags=[config.dst_switch_tag],
        model='MS',
        total_pages=-1
    )
    # Obtain set of networks those MS devices are mapped to
    device_nets = [*set(d['networkId'] for d in org_devices)]

    # Obtain list of networks in the organization with the config.dst_network_tag
    org_networks = await aiomeraki.organizations.getOrganizationNetworks(
        organizationId=config.src_org_id,
        tags=[config.dst_network_tag],
        total_pages=-1
    )

    # Construct a set of the network IDs of said networks
    tagged_nets = [*set(net['id'] for net in org_networks)]
    # Find intersection between set of networks tagged MS devices belong to, and tagged networks
    definitive_nets = list(set(device_nets)&set(tagged_nets))
    # Filter list of MS with definitive network list
    target_devices = [dev for dev in org_devices if dev['networkId'] in definitive_nets]
    # Obtain list of serial numbers from definitive MS list
    target_device_serials = [dev['serial'] for dev in target_devices]
    # Filter list of tagged networks with the network IDs in definitive_nets
    target_networks = [net for net in org_networks if net['id'] in definitive_nets]

    if config.verbose==True:
        print("Target Devices:")
        print(tabulate(pd.DataFrame(target_devices), headers='keys', tablefmt ='fancy_grid'))
        print("Target Networks:")
        print(tabulate(pd.DataFrame(target_networks), headers='keys', tablefmt='fancy_grid'))

    # Obtain list of switch profiles in the template config.src_template_id
    temp_switch_profiles = await aiomeraki.switch.getOrganizationConfigTemplateSwitchProfiles(
        organizationId=config.src_org_id,
        configTemplateId=config.src_template_id
    )

    # Obtain list of ports on each profile, and construct a dictionary with keys for each switch profile, containing
    # ports and model subkeys for each profile
    temp_switch_profile_ports_dict = {}
    for profile in temp_switch_profiles:
        temp_switch_profile_ports_dict[profile['name']]={
            'ports': await aiomeraki.switch.getOrganizationConfigTemplateSwitchProfilePorts(
                organizationId=config.src_org_id,
                configTemplateId=config.src_template_id,
                profileId=profile['switchProfileId']),
            'model': profile['model']
        }
    if config.verbose==True:
        print("Port profiles in source template:")
        for key in temp_switch_profile_ports_dict.keys():
            print(f"Port Profile {key}")
            print(tabulate(pd.DataFrame(temp_switch_profile_ports_dict[key]["ports"]), headers='keys', tablefmt='fancy_grid'))

    # Obtain list of Access Policies in source template
    temp_access_policies = await aiomeraki.switch.getNetworkSwitchAccessPolicies(
        networkId=config.src_template_id
    )

    # Since RADIUS secrets are not returned by the API, request user input to fill these in
    for ap in temp_access_policies:
        if ap['radiusServers']!=[]:
            for server in ap['radiusServers']:
                radius_secret = input(f"Please input your desired RADIUS secret for Access Policy {ap['name']} and server {server['host']}: ")
                server['secret'] = radius_secret
        if ap['radiusAccountingEnabled'] == True:
            for server in ap['radiusAccountingServers']:
                radius_secret = input(f"Please input your desired Accounting RADIUS secret for Access Policy {ap['name']} and accounting server {server['host']}: ")
                server['secret'] = radius_secret

    # Obtain list of Port Schedules in source template
    temp_port_schedules = await aiomeraki.switch.getNetworkSwitchPortSchedules(
        networkId=config.src_template_id
    )
    if config.verbose == True:
        print("Access Policies in Source Template:")
        print(tabulate(pd.DataFrame(temp_access_policies), headers='keys', tablefmt='fancy_grid'))
        print("Port Schedules in Source Template:")
        print(tabulate(pd.DataFrame(temp_port_schedules), headers='keys', tablefmt='fancy_grid'))

    # Since schedule IDs and access policy IDs are only locally significant, map port configuration to schedule
    # and access policy name instead
    for key in temp_switch_profile_ports_dict.keys():
        for port in temp_switch_profile_ports_dict[key]['ports']:
            for ps in temp_port_schedules:
                if ps['id'] == port['portScheduleId']:
                    port['portScheduleId'] = ps['name']
            if 'accessPolicyNumber' in port:
                for ap in temp_access_policies:
                    if ap['accessPolicyNumber'] == str(port['accessPolicyNumber']):
                        port['accessPolicyNumber'] = ap['name']

    # Build dictionary with target networks as keys, and access policies and port schedules as subkeys
    net_attributes = {}
    for net in target_networks:
        net_attributes[f'{net["id"]}']={}
        net_attributes[f'{net["id"]}']['access_policies']= await aiomeraki.switch.getNetworkSwitchAccessPolicies(
            networkId=net['id']
        )
        net_attributes[f'{net["id"]}']['port_schedules'] = await aiomeraki.switch.getNetworkSwitchPortSchedules(
            networkId=net['id']
        )
        # Add GPs
        net_attributes[f'{net["id"]}']["group_policies"] = await aiomeraki.networks.getNetworkGroupPolicies(
            networkId=net['id']
        )
        # Add QoS
        net_attributes[f'{net["id"]}']["qos_rules"] = await aiomeraki.switch.getNetworkSwitchQosRules(
            networkId=net['id']
        )
        net_attributes[f'{net["id"]}']["qos_rules_order"] = await aiomeraki.switch.getNetworkSwitchQosRulesOrder(
            networkId=net['id']
        )
        # Add Net Alerts
        net_attributes[f'{net["id"]}']["net_alerts"] = await aiomeraki.networks.getNetworkAlertsSettings(
            networkId=net['id']
        )
        # Add Syslog
        net_attributes[f'{net["id"]}']['syslog'] = await aiomeraki.networks.getNetworkSyslogServers(
            networkId=net["id"]
        )
        # Add ACL
        net_attributes[f'{net["id"]}']['acl'] = await aiomeraki.switch.getNetworkSwitchAccessControlLists(
            networkId=net['id']
        )

        # Add SNMP
        net_attributes[f'{net["id"]}']['snmp'] = await aiomeraki.networks.getNetworkSnmp(
            networkId=net["id"]
        )

        # Add Net Analytics
        net_attributes[f'{net["id"]}']['net_analytics'] = await aiomeraki.networks.getNetworkTrafficAnalysis(
            networkId=net["id"]
        )


    if config.verbose == True:
        for key in net_attributes.keys():
            print(f"Access Policies currently in Network {key}:")
            print(tabulate(pd.DataFrame(net_attributes[key]['access_policies']), headers='keys', tablefmt='fancy_grid'))
            print(f"Port Schedules currently in Network {key}:")
            print(tabulate(pd.DataFrame(net_attributes[key]['port_schedules']), headers='keys', tablefmt='fancy_grid'))

    # Obtain list of all target switches in the organization along with their lists of ports
    target_switch_ports = await aiomeraki.switch.getOrganizationSwitchPortsBySwitch(
        organizationId=config.dst_org_id,
        serials=target_device_serials,
        total_pages=-1
    )

    if config.verbose == True:
        print("Ports to be modified by script on target switches:")
        for switch in target_switch_ports:
            print(f"Network {switch['network']['name']} - Switch {switch['name']} - {switch['serial']}:")
            print(tabulate(pd.DataFrame(switch["ports"]), headers='keys', tablefmt='fancy_grid'))

    return target_devices, target_networks, temp_switch_profiles, temp_switch_profile_ports_dict, \
        temp_access_policies, temp_port_schedules, net_attributes, target_switch_ports

async def gather_network_data(aiomeraki):
    """
    Gathers the information necessary to propagate switch configs from the source template specified in the config.py
    file.
    :param aiomeraki: asyncio instance of the Dashboard API client with access to the source and target organizations,
    as well as the source configuration templates
    :returns: src_acl_config: ACL Config in source template
              src_qos_config: QoS Config in source template
              src_qos_order_config: Order of QoS rules in source template
              src_group_policies: Group Policies in source template
              src_network_alerts: Network Alerts in source template
              src_syslog_config: Syslog Config in source template
              src_snmp_config: SNMP Config in source template
              src_net_analytics: Network Analytics Config in source template
    """
    # Obtain ACLs in source template
    src_acl_config = await aiomeraki.switch.getNetworkSwitchAccessControlLists(
        networkId=config.network_src_template_id
    )

    # Obtain QoS Configs in source template
    src_qos_config = await aiomeraki.switch.getNetworkSwitchQosRules(
        networkId=config.network_src_template_id
    )
    src_qos_order_config = await aiomeraki.switch.getNetworkSwitchQosRulesOrder(
        networkId=config.network_src_template_id
    )

    # Obtain Group Policies in source template
    src_group_policies = await aiomeraki.networks.getNetworkGroupPolicies(
        networkId=config.network_src_template_id
    )

    # Obtain Network Alerts in source template
    src_network_alerts = await aiomeraki.networks.getNetworkAlertsSettings(
        networkId=config.network_src_template_id
    )

    # Obtain Syslog Configs in source template
    src_syslog_config = await aiomeraki.networks.getNetworkSyslogServers(
        networkId=config.network_src_template_id
    )

    # Obtain SNMP Configs in source template
    src_snmp_config = await aiomeraki.networks.getNetworkSnmp(
        networkId=config.network_src_template_id
    )

    # Obtain Analytics configs in source template
    src_net_analytics = await aiomeraki.networks.getNetworkTrafficAnalysis(
        networkId=config.network_src_template_id
    )

    if config.verbose==True:
        print("Source Template ACL Rules:")
        try:
            print(tabulate(pd.DataFrame(src_acl_config["rules"]), headers='keys', tablefmt='fancy_grid'))
        except:
            print("No ACL Rules found!")
        print("Source Template QOS Rules:")
        try:
            print(tabulate(pd.DataFrame(src_qos_config), headers='keys', tablefmt='fancy_grid'))
        except:
            print("No QOS Rules Found!")
        print("Source Template QOS Rule Order:")
        try:
            print(tabulate(pd.DataFrame(src_qos_order_config["ruleIds"]), headers='keys', tablefmt='fancy_grid'))
        except:
            print("No QoS Rules Found!")
        print("Source Template Group Policies:")
        try:
            print(tabulate(pd.DataFrame(src_group_policies), headers='keys', tablefmt='fancy_grid'))
        except:
            print("No Group Policies Found!")
        print("Source Template Network Alerts:")
        try:
            print(tabulate(pd.DataFrame(src_network_alerts["alerts"]), headers='keys', tablefmt='fancy_grid'))
        except:
            print("No Alerts Found!")
        print("Source Template Syslog Config:")
        try:
            print(tabulate(pd.DataFrame(src_syslog_config["servers"]), headers='keys', tablefmt='fancy_grid'))
        except:
            print("No Syslog Config Found!")
        print("Source Template SNMP Config:")
        try:
            print(tabulate(pd.DataFrame([src_snmp_config]), headers='keys', tablefmt='fancy_grid'))
        except:
            print("No SNMP Config Found!")
        print("Source Template Network Analytics Config:")
        try:
            print(tabulate(pd.DataFrame(src_net_analytics["customPieChartItems"]), headers='keys', tablefmt='fancy_grid'))
        except:
            print("No Network Analytics Config Found!")

    return src_acl_config, src_qos_config, src_qos_order_config, src_group_policies, src_network_alerts, \
        src_syslog_config, src_snmp_config, src_net_analytics

async def main(aiomeraki):
    async with aiomeraki:
        target_devices, target_networks, temp_switch_profiles, temp_switch_profile_ports_dict, \
        temp_access_policies, temp_port_schedules, net_attributes, target_switch_ports \
            = await gather_switch_specific_data(aiomeraki)

        src_acl_config, src_qos_config, src_qos_order_config, src_group_policies, src_network_alerts, \
        src_syslog_config, src_snmp_config, src_net_analytics \
            = await gather_network_data(aiomeraki)

    return target_devices, target_networks, temp_switch_profiles, temp_switch_profile_ports_dict, \
        temp_access_policies, temp_port_schedules, net_attributes, target_switch_ports, \
        src_acl_config, src_qos_config, src_qos_order_config, src_group_policies, src_network_alerts, \
        src_syslog_config, src_snmp_config, src_net_analytics