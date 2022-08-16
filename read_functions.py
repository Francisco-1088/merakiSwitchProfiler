import asyncio
import config
import pandas as pd
from tabulate import tabulate

async def get_network_switch_access_policies(aiomeraki, net_id):
    """
    Async function wrapper for switch access policies
    :param aiomeraki: Async Dashboard API client
    :param net_id: network ID of target network
    :return: Access policies belonging to this network ID
    """
    results = await aiomeraki.switch.getNetworkSwitchAccessPolicies(net_id)
    return net_id, "access_policies", results

async def get_network_switch_port_schedules(aiomeraki, net_id):
    """
    Async function wrapper for switch port schedules
    :param aiomeraki: Async Dashboard API client
    :param net_id: network ID of target network
    :return: Port Schedules belonging to this network ID
    """
    results = await aiomeraki.switch.getNetworkSwitchPortSchedules(net_id)
    return net_id, "port_schedules", results

async def get_network_group_policies(aiomeraki, net_id):
    """
    Async function wrapper for nwtwork group policies
    :param aiomeraki: Async Dashboard API client
    :param net_id: network ID of target network
    :return: Group Policies belonging to this network ID
    """
    results = await aiomeraki.networks.getNetworkGroupPolicies(net_id)
    return net_id, "group_policies", results

async def get_network_syslog(aiomeraki, net_id):
    """
    Async function wrapper for syslog configs
    :param aiomeraki: Async Dashboard API client
    :param net_id: network ID of target network
    :return: Syslog settings belonging to this network ID
    """
    results = await aiomeraki.networks.getNetworkSyslogServers(net_id)
    return net_id, "syslog", results

async def get_network_snmp(aiomeraki, net_id):
    """
    Async function wrapper for switch access policies
    :param aiomeraki: Async Dashboard API client
    :param net_id: network ID of target network
    :return: Access policies belonging to this network ID
    """
    results = await aiomeraki.networks.getNetworkSnmp(net_id)
    return net_id, "snmp", results

async def get_network_alerts(aiomeraki, net_id):
    """
    Async function wrapper for switch access policies
    :param aiomeraki: Async Dashboard API client
    :param net_id: network ID of target network
    :return: Access policies belonging to this network ID
    """
    results = await aiomeraki.networks.getNetworkAlertsSettings(net_id)
    return net_id, "net_alerts", results

async def get_network_analytics(aiomeraki, net_id):
    """
    Async function wrapper for Network Analytics
    :param aiomeraki: Async Dashboard API client
    :param net_id: network ID of target network
    :return: Network Analytics belonging to this network ID
    """
    results = await aiomeraki.networks.getNetworkTrafficAnalysis(net_id)
    return net_id, "net_analytics", results

async def get_network_switch_qos_rules(aiomeraki, net_id):
    """
    Async function wrapper for Switch QOS Rules
    :param aiomeraki: Async Dashboard API client
    :param net_id: network ID of target network
    :return: QOS Rules belonging to this network ID
    """
    results = await aiomeraki.switch.getNetworkSwitchQosRules(net_id)
    return net_id, "qos_rules", results

async def get_network_switch_qos_rules_order(aiomeraki, net_id):
    """
    Async function wrapper for switch QOS Rules order
    :param aiomeraki: Async Dashboard API client
    :param net_id: network ID of target network
    :return: QoS rules order belonging to this network ID
    """
    results = await aiomeraki.switch.getNetworkSwitchQosRulesOrder(net_id)
    return net_id, "qos_rules_order", results

async def get_network_switch_acl(aiomeraki, net_id):
    """
    Async function wrapper for switch ACLs
    :param aiomeraki: Async Dashboard API client
    :param net_id: network ID of target network
    :return: ACLs belonging to this network ID
    """
    results = await aiomeraki.switch.getNetworkSwitchAccessControlLists(net_id)
    return net_id, "acl", results

async def get_org_config_template_switch_profile_ports(aiomeraki, src_org_id, src_template_id, profile):
    """
    Async function wrapper for switch profile ports
    :param aiomeraki: Async Dashboard API client
    :param src_org_id: Org ID housing template with switch profiles
    :param src_template_id: Template housing desired switch profiles
    :param profile: Switch profile you're interested in getting ports from
    :return: Port configurations on the profile
    """
    results = await aiomeraki.switch.getOrganizationConfigTemplateSwitchProfilePorts(
        organizationId=src_org_id,
        configTemplateId=src_template_id,
        profileId=profile['switchProfileId'])
    return profile, results

async def get_target_network_data(aiomeraki, target_networks):
    """
    Obtains existing configs on target networks using async functions
    :param aiomeraki: Async Dashboard API client
    :param target_networks: List containing all target networks
    :return: net_attributes: Dictionary with all of the networks as keys, and values are subdictionaries containing
    each of the network parameters.
    """
    net_attributes = {}
    # Build list of async functions to call
    get_tasks = []
    for network in target_networks:
        get_tasks.append(get_network_switch_access_policies(aiomeraki, network['id']))
        get_tasks.append(get_network_switch_port_schedules(aiomeraki, network['id']))
        get_tasks.append(get_network_group_policies(aiomeraki, network['id']))
        get_tasks.append(get_network_snmp(aiomeraki, network['id']))
        get_tasks.append(get_network_syslog(aiomeraki, network['id']))
        get_tasks.append(get_network_alerts(aiomeraki, network['id']))
        get_tasks.append(get_network_analytics(aiomeraki, network['id']))
        get_tasks.append(get_network_switch_qos_rules(aiomeraki, network['id']))
        get_tasks.append(get_network_switch_qos_rules_order(aiomeraki, network['id']))
        get_tasks.append(get_network_switch_acl(aiomeraki, network['id']))

    # Await and sort
    for task in asyncio.as_completed(get_tasks):
        net_id, action, result = await task
        if net_id not in net_attributes.keys():
            net_attributes[net_id] = {}
        net_attributes[net_id][action] = result

    return net_attributes

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

    # Obtain list of networks in the organization with the config.dst_network_tag
    org_networks = await aiomeraki.organizations.getOrganizationNetworks(
        organizationId=config.src_org_id,
        tags=[config.dst_network_tag],
        total_pages=-1
    )

    # Obtain list of Access Policies in source template
    temp_access_policies = await aiomeraki.switch.getNetworkSwitchAccessPolicies(
        networkId=config.src_template_id
    )

    # Obtain list of Port Schedules in source template
    temp_port_schedules = await aiomeraki.switch.getNetworkSwitchPortSchedules(
        networkId=config.src_template_id
    )

    # Obtain set of networks those MS devices are mapped to
    device_nets = [*set(d['networkId'] for d in org_devices)]

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
    get_tasks = []
    for profile in temp_switch_profiles:
        get_tasks.append(get_org_config_template_switch_profile_ports(
            aiomeraki=aiomeraki,
            src_org_id=config.src_org_id,
            src_template_id=config.src_template_id,
            profile=profile)
        )

    for task in asyncio.as_completed(get_tasks):
        profile, results = await task
        if profile["name"] not in temp_switch_profile_ports_dict.keys():
            temp_switch_profile_ports_dict[profile["name"]]={}
        temp_switch_profile_ports_dict[profile['name']]={
            "ports": results,
            "model": profile['model']
        }

    if config.verbose==True:
        print("Port profiles in source template:")
        for key in temp_switch_profile_ports_dict.keys():
            print(f"Port Profile {key}")
            print(tabulate(pd.DataFrame(temp_switch_profile_ports_dict[key]["ports"]), headers='keys', tablefmt='fancy_grid'))

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
    net_attributes = await get_target_network_data(aiomeraki, target_networks)

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
    # Network attributes to be obtained from template
    get_tasks = [
        get_network_group_policies(aiomeraki, config.network_src_template_id),
        get_network_snmp(aiomeraki, config.network_src_template_id),
        get_network_syslog(aiomeraki, config.network_src_template_id),
        get_network_alerts(aiomeraki, config.network_src_template_id),
        get_network_analytics(aiomeraki, config.network_src_template_id),
        get_network_switch_qos_rules(aiomeraki, config.network_src_template_id),
        get_network_switch_qos_rules_order(aiomeraki, config.network_src_template_id),
        get_network_switch_acl(aiomeraki, config.network_src_template_id)
    ]

    # Await and sort
    for task in asyncio.as_completed(get_tasks):
        net_id, action, result = await task
        if action=='acl':
            src_acl_config = result
        elif action=='qos_rules':
            src_qos_config = result
        elif action=='qos_rules_order':
            src_qos_order_config = result
        elif action=='group_policies':
            src_group_policies = result
        elif action=='net_alerts':
            src_network_alerts = result
        elif action=='syslog':
            src_syslog_config = result
        elif action=='snmp':
            src_snmp_config = result
        elif action=='net_analytics':
            src_net_analytics = result

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