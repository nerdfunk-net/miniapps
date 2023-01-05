from collections import defaultdict

def inf_defaultdict():
    return defaultdict(inf_defaultdict)

result = inf_defaultdict()

result["1"]["2"]["3"]["4"]["5"]["6"] = "test"
print(result)