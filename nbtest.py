#!/usr/bin/env python

import requests
import json


r = requests.get(url="http://127.0.0.1:8000/get/network_design/defaults/defaults.yaml")
if r.status_code != 200:
    print ('got status code %i' % r.status_code)
else:
    # we got a json. parse it and check if we have a success or not
    response = json.loads(r.content)
    print (response)

