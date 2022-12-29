from nornir import InitNornir
from nornir_scrapli.tasks import send_command

nr = InitNornir(
        inventory={
            "plugin": "NautobotInventory",
            "options": {
                "nautobot_url": "http://127.0.0.1:8080",
                "nautobot_token": "18acb72f4f8df7d5b939492edaebc88a0992640d",
                "filter_parameters": {"name": "lab"},
                "ssl_verify": False,
            }
        }
    )

nr.inventory.defaults.username = "lab"
nr.inventory.defaults.password = "lab"

command_results = nr.run(task=send_command, command="show run")
print(command_results["lab"][0])