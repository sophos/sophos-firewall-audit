"""Sophos Firewall Audit

Environment Variables (Required):
VAULT_MOUNT_POINT = HashiCorp Vault Mount Point (ex. kv)
VAULT_SECRET_PATH = HashiCorp Vault Secret path
VAULT_USERNAME = HashiCorp Vault username
ROLEID = HashiCorp Vault Role ID
SECRETID = HashiCorp Vault Secret ID

"""
import os
import yaml
import json
import logging
from datetime import datetime
from jinja2 import Environment, PackageLoader, select_autoescape
from rich.logging import RichHandler
from rich.highlighter import RegexHighlighter
from rich.theme import Theme
from rich.console import Console
from prettytable import PrettyTable
from prettytable import ALL
from sophosfirewall_python.firewallapi import SophosFirewall
from auth import get_credential
import rules

class DeviceNameHighlighter(RegexHighlighter):
    """Apply style to the device name."""

    base_style = "style."
    highlights = [r"(?P<hostname>[a-z]+-[a-z]+-[a-z]+-[a-z]+-\S+)", r"(?P<hostname>[a-z]+-[a-z]+-[a-z]+-[a-z]+-[a-z]+-\S+)"]

theme = Theme({"style.hostname": "magenta"})
console = Console(theme=theme)
FORMAT = '%(message)s'
logging.basicConfig(level=logging.INFO, format=FORMAT, handlers=[RichHandler(console=console, 
                                                                             highlighter=DeviceNameHighlighter(),
                                                                             show_path=False,
                                                                             omit_repeated_times=False)])

def update_status_dict(result, status_dict, firewall_name):
    """Update overall status counters in the status_dict

    Args:
        result (dict): Rule evaluation result
        status_dict (dict): Pass/Fail status tracker
        firewall_name (str): Firewall hostname

    Returns:
        dict: Returns the passed in status_dict with the counters updated
    """
    if result["audit_result"] == "PASS":
        status_dict[firewall_name]["success_ct"] += 1
    else:
        status_dict[firewall_name]["failed_ct"] += 1
    return status_dict

def process_rule(method, settings, log_msg, fw_obj, status_dict):
    """Process an evaluation rule. 

    Args:
        method (function): The rule function to be executed
        settings (dict): The expected result from the settings YAML
        log_msg (str): Log message to be printed
        fw_obj (obj): SophosFirewall object
        status_dict (dict): Pass/Fail status counters

    Returns:
        dict: Task output and status_dict with updated counters
    """
    logging.info(f"{fw_obj.hostname}: {log_msg}")
    result = method(fw_obj, fw_obj.hostname, settings)
    status_dict = update_status_dict(result, status_dict, fw_obj.hostname)
    return {"result": result, "output": result["output"], "status_dict": status_dict}

if __name__ == '__main__':

    env = Environment(
        loader=PackageLoader("audit"),
        autoescape=select_autoescape()
    )  

    logging.info("Starting Sophos Firewall audit")
    logging.info ("Retrieving credentials from Vault...")
    fw_password = get_credential(
        mount_point=os.environ['VAULT_MOUNT_POINT'],
        secret_path=os.environ['VAULT_SECRET_PATH'],
        key = os.environ['VAULT_USERNAME']
    )
    logging.info("Successfully retrieved credentials!")

    with open("firewalls.yaml", "r") as fn:
        firewalls = yaml.safe_load(fn)

    with open("audit_settings.yaml", "r") as fn:
        audit_settings = yaml.safe_load(fn)

    

    status_dict = {}

    dt = datetime.now()
    dirname = f"audit-results-{dt.strftime('%Y-%m-%d-%H%M%S')}"
    os.mkdir(dirname)

    for firewall in firewalls:
        fw = SophosFirewall(
            username=os.environ['VAULT_USERNAME'],
            password=fw_password,
            hostname=firewall['hostname'],
            port=firewall['port']
        )

        results = []
        output = []
        firewall_name = firewall["hostname"]
        status_dict[firewall_name] = {
            "success_ct": 0,
            "failed_ct": 0
        }

        logging.info(f"{firewall_name}: Begin Audit")

        rule_list = [
            {
                "method": rules.eval_access_list, 
                "settings": audit_settings["access_acl"],
                "log_msg": "Evaluate Access ACL"
            },
            {
                "method": rules.eval_device_access_profile,
                "settings": audit_settings["device_access_profile"],
                "log_msg": "Evaluate Device Access Profiles"
            },
            {
                "method": rules.eval_admin_services,
                "settings": audit_settings["admin_services"],
                "log_msg": "Evaluate WAN Zone Admin Services"
            },
            {
                "method": rules.eval_admin_authen,
                "settings": audit_settings["authen_servers"],
                "log_msg": "Evaluate Authentication Servers"
            },
            {
                "method": rules.eval_atp,
                "settings": audit_settings["threat_protection"],
                "log_msg": "Evaluate Advanced Threat Protection (ATP)"
            },
            {
                "method": rules.eval_ips_policies,
                "settings": audit_settings["ips_policies"],
                "log_msg": "Evaluate IPS Policies"
            },
            {
                "method": rules.eval_hostgroups,
                "settings": audit_settings["host_groups"],
                "log_msg": "Evaluate Host Groups"
            },
            {
                "method": rules.eval_syslog,
                "settings": audit_settings["syslog"],
                "log_msg": "Evaluate Syslog Settings"
            },
            {
                "method": rules.eval_notifications,
                "settings": audit_settings,
                "log_msg": "Evaluate Notifications Settings"
            },
            {
                "method": rules.eval_notification_list,
                "settings": audit_settings,
                "log_msg": "Evaluate Notification List Settings"
            },
            {
                "method": rules.eval_backup,
                "settings": audit_settings,
                "log_msg": "Evaluate Scheduled Backup Settings"
            },
            {
                "method": rules.eval_certificate,
                "settings": audit_settings,
                "log_msg": "Evaluate Certificate Settings"
            },
            {
                "method": rules.eval_loginsecurity,
                "settings": audit_settings,
                "log_msg": "Evaluate Login Security"
            },
            {
                "method": rules.eval_dns_servers,
                "settings": audit_settings,
                "log_msg": "Evaluate DNS Servers"
            },
            {
                "method": rules.eval_snmpv3,
                "settings": audit_settings,
                "log_msg": "Evaluate SNMPv3"
            }

        ]
        for rule in rule_list:
            result = process_rule(rule["method"], rule["settings"], rule["log_msg"], fw, status_dict)
            output += result["output"]
            status_dict = result["status_dict"]
            results.append(result)
        
        table = PrettyTable()
        table.hrules = ALL
        table.field_names = ["Test Name", "UI Location", "Object", "Expected", "Actual", "Result"]
        table.add_rows(output)
        table.valign = "m"
        table.align["Expected"] = "l"
        table.align["Actual"] = "l"

        template = env.get_template("results.j2")
        result_html = template.render(firewall_name=firewall_name, table=table.get_html_string(format=True))

        with open (f"{dirname}/{firewall_name}.html", "w") as fn:
            fn.write(result_html)

        with open(f"{dirname}/{firewall['hostname']}.json", "w") as fn:
            fn.write(json.dumps(results, indent=4))

    template = env.get_template("index.j2")

    firewall_list = [firewall['hostname'] for firewall in firewalls]
    index_html = template.render(status_dict=status_dict)

    with open(f"{dirname}/index.html", "w") as fn:
        fn.write(index_html)

    with open("results.json", "w") as fn:
        fn.write(json.dumps(status_dict))



    

        