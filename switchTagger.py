import config
import batch_helper
import meraki
import pandas as pd

# Instantiate synchronous Meraki API client
dashboard = meraki.DashboardAPI(
    config.api_key,
    base_url="https://api.meraki.com/api/v1",
    log_file_prefix=__file__[:-3],
    print_console=config.console_logging,
    )

org_devices = dashboard.organizations.getOrganizationDevices(
        organizationId=config.dst_org_id,
        model='MS',
        total_pages=-1
    )

switches = pd.read_csv('./switches.csv')

switches_list = switches.to_dict('records')

for switch in switches_list:
    for dev in org_devices:
        if switch['serial']==dev['serial']:
            print(switch['tags'].split(','))
            print(dev['tags'])
            dev['tags']=switch['tags'].split(',')+dev['tags']

actions = []

for dev in org_devices:
    if 'switchProfiler' in dev['tags']:
        upd = {k: dev[k] for k in dev.keys() - {
                    "serial"
                }}
        action = dashboard.batch.devices.updateDevice(serial=dev['serial'], **upd)
        actions.append(action)

test_helper = batch_helper.BatchHelper(
    dashboard,
    config.dst_org_id,
    actions,
    linear_new_batches=False,
    actions_per_new_batch=100
)

test_helper.prepare()
test_helper.generate_preview()
test_helper.execute()

print(f'helper status is {test_helper.status}')

batches_report = dashboard.organizations.getOrganizationActionBatches(config.dst_org_id)
new_batches_statuses = [{'id': batch['id'], 'status': batch['status']} for batch in batches_report if
                        batch['id'] in test_helper.submitted_new_batches_ids]
failed_batch_ids = [batch['id'] for batch in new_batches_statuses if batch['status']['failed']]
print(f'Failed batch IDs are as follows: {failed_batch_ids}')