import requests
import json


def send_request(url, config, json_data, result, item="", success=""):

    # please notice: check config.yaml and check if a // is not part of the URL!
    url_request = "%s/onboarding/%s" % (config["sot"]["api_endpoint"], url)
    r = requests.post(url=url_request, json=json_data)

    if r.status_code != 200:
        result['logs'].append('got status code %i' % r.status_code)
    else:
        # we got a json. parse it and check if we have a success or not
        response = json.loads(r.content)
        if response["success"]:
            result['success'].append(True)
            result['logs'].append("%s %s" % (item,success))
        else:
            result['success'].append(False)
            if "reason" in response:
                result['logs'].append("%s failed; %s" % (item, response["reason"]))
            else:
                result['logs'].append("interface updated; unknown reason")
