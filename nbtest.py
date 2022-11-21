#!/usr/bin/env python

import requests
import json

update = {
     "name": "pod1r1",
     "device_role": "pod_router",
     "manufacturer": "arista",
     "device_type": "arista_router",
     "serial": "serialnumber",
     "site": "pod1",
     "location": "location",
     "status": "active",
     "primary_ip4": "1.1.1.2/32",
     "comments": "comments",
     "tags": "d1,d1"
}

data = {
     "name": "new_name",
     "config": update
}

url_add_adress = "http://127.0.0.1:8000/onboarding/updatedevice"
r = requests.post(url=url_add_adress, json=data)
if r.status_code != 200:
     print('got status code %i' % r.status_code)
else:
     response = json.loads(r.content)
     print(json.dumps(response, indent=4))