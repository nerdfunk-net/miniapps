#!/usr/bin/env python

import requests
import json

#config = '{"location": "location", "site":"pod1"}'
#config = '{"location": "location"}'
config = '{"site":"site1"}'

data = {
     "name": "pod1r1",
     "config": config
}

url_add_adress = "http://127.0.0.1:8000/onboarding/updatedevice"
r = requests.post(url=url_add_adress, json=data)
if r.status_code != 200:
     print('got status code %i' % r.status_code)
else:
     response = json.loads(r.content)
     print(json.dumps(response, indent=4))