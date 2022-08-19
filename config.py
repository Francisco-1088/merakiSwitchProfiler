# Authentication Config
api_key = 'ADD_MERAKI_API_KEY_HERE'

# Orgs and Networks
src_org_id = 'ADD_ORG_ID_THAT_HOUSES_SOURCE_TEMPLATE'
dst_org_id = 'ADD_ORG_ID_THAT_HOUSES_DESTINATION_NETWORKS' # Can be the same as src_org_id
src_template_id = 'ADD_ID_OF_SOURCE_TEMPLATE_WITH_SWITCH_PROFILES'
network_src_template_id = 'ADD_ID_OF_SOURCE_TEMPLATE_WITH_QOS_ACL_ALERT_SNMP_SYSLOG_CONFIGS' 
# This can be a different template from the one holding switch port configs, in case you need 
# to decouple those two aspects, or it can be the same template ID

# Modules to Sync ----NOT IMPLEMENTED YET----
# Keep only the modules you want to sync
# Available modules: switch_ports, port_schedules, access_policies, qos, acl, group_policies, net_analytics,
# syslog, snmp, alerts
# For syncing switch_ports, it is also necessary to sync port_schedules and access_policies
modules = ['switch_ports', 'port_schedules', 'access_policies',
           'qos', 'acl', 'group_policies', 'net_analytics', 'syslog', 'snmp', 'alerts']

# Tag Config, you may change these to whatever tag names you prefer
dst_network_tag = 'switchProfiler'
dst_switch_tag = 'switchProfiler'
ignore_port_tag = 'ignore'

# Logging, Verbosity and Supervision
verbose = True # Will display information gathered about networks
supervised = True # Will ask for confirmation before applying any configuration changes
console_logging = True # Will print API output to the console
max_retries = 1000 # For large deployments it's best to keep this number high to work around 429 errors
