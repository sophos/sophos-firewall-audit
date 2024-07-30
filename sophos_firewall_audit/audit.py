"""Sophos Firewall Audit

Copyright 2024 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
"""
import os
import yaml
import logging
import json
import pkg_resources
import html
html.escape = lambda *args, **kwargs: args[0]
from jinja2 import Environment, PackageLoader, Template, select_autoescape
from sophos_firewall_audit import rules
from prettytable import PrettyTable
from prettytable import ALL
from sophos_firewall_audit.logging_config import LoggingSetup

logging_setup = LoggingSetup()
logger = logging.getLogger(__name__)

env = Environment(
        loader=PackageLoader("sophos_firewall_audit"),
        autoescape=select_autoescape()
    )


def update_status_dict(result, status_dict, firewall_name):
    """Update overall status counters in the status_dict

    Args:
        result (dict): Rule evaluation result
        status_dict (dict): Pass/Fail status tracker
        firewall_name (str): Firewall hostname

    Returns:
        dict: Returns the passed in status_dict with the counters updated
    """
    status_dict[firewall_name]["success_ct"] += result["pass_ct"]
    status_dict[firewall_name]["failed_ct"] += result["fail_ct"]
    logging.info(f"{firewall_name}: Success: {status_dict[firewall_name]['success_ct']} Failed: {status_dict[firewall_name]['failed_ct']}")
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

def run_audit(args, fw_obj, firewall, status_dict, local_dirname, web_dirname):
    with open(args.settings_file, "r", encoding="utf-8") as fn:
        templ = Template(source=fn.read())
        rendered = templ.render({"firewall_hostname": fw_obj.hostname.split(".")[0]})
        audit_settings = yaml.safe_load(rendered)

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
            "method": rules.eval_central_mgmt, 
            "settings": audit_settings,
            "log_msg": "Evaluate Central Management"
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
            "method": rules.eval_malware_protection,
            "settings": audit_settings["malware_protection"],
            "log_msg": "Evaluate Malware Protection Antivirus Engine"
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
            "method": rules.eval_smtp_protection,
            "settings": audit_settings,
            "log_msg": "Evaluate SMTP Protection"
        },
        {
            "method": rules.eval_snmpv3,
            "settings": audit_settings,
            "log_msg": "Evaluate SNMPv3"
        },
        {
            "method": rules.eval_time,
            "settings": audit_settings['time'],
            "log_msg": "Evaluate Time Settings"
        }
    ]
    for rule in rule_list:
        result = process_rule(rule["method"], rule["settings"], rule["log_msg"], fw_obj, status_dict)
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
    result_html = template.render(firewall_name=firewall_name, 
                                  table=table.get_html_string(format=True, escape_data=False),
                                  title="Firewall Audit Test Results")

    for dirname in [local_dirname, web_dirname]:
        with open (f"{os.path.join(dirname, firewall_name)}.html", "w", encoding="utf-8") as fn:
            fn.write(result_html)

        with open(f"{os.path.join(dirname, firewall['hostname'])}.json", "w", encoding="utf-8") as fn:
            fn.write(json.dumps(results, indent=4))

    return status_dict

def generate_audit_output(status_dict, local_dirname, web_dirname):
    template = env.get_template("audit_index.j2")

    with open("results.json", "w", encoding="utf-8") as fn:
        fn.write(json.dumps(status_dict))

    for dirname in [local_dirname, web_dirname]:
        index_html = template.render(status_dict=status_dict, dirname=dirname, title="Firewall Audit Report")

        with open(os.path.join(dirname, 'index.html'), "w", encoding="utf-8") as fn:
            fn.write(index_html)

        home_template = env.get_template("home.j2")

        if "web" in dirname:
            try:
                with open(os.path.join("results_html_web", "index.html"), "r", encoding="utf-8") as fn:
                    home_html = fn.readlines()
            except FileNotFoundError:
                home_html = home_template.render(title="Firewall Audit").splitlines(True)
                with open(os.path.join("results_html_web", "index.html"), "w", encoding="utf-8") as fn:
                    fn.writelines(home_html)
        else:
            try:
                with open(os.path.join("results_html_local", "index.html"), "r", encoding="utf-8") as fn:
                    home_html = fn.readlines()
            except FileNotFoundError:
                home_html = home_template.render(title="Firewall Audit").splitlines(True)
                with open(os.path.join("results_html_local", "index.html"), "w", encoding="utf-8") as fn:
                    fn.writelines(home_html)                  

        updated_home_html = []

        for line in home_html:
            if "<h1>Firewall Audit</h1>" in line:
                updated_home_html.append(line)
                if "web" in dirname:
                    updated_home_html.append(
                        f'<a style="text-align: left;" href="/{dirname.split(os.sep)[1]}/index.html">{dirname.split(os.sep)[1]}</a><br/>\n'
                    )
                else:
                    updated_home_html.append(
                        f'<a style="text-align: left;" href="file:{dirname.split(os.sep)[1]}/index.html">{dirname.split(os.sep)[1]}</a><br/>\n'
                    )
            else:
                updated_home_html.append(line)

        if "web" in dirname:
            with open(os.path.join("results_html_web", "index.html"), "w", encoding="utf-8") as fn:
                fn.writelines(updated_home_html)
        else:
            with open(os.path.join("results_html_local", "index.html"), "w", encoding="utf-8") as fn:
                logging.info(f"Audit results: results_html_local{os.sep}{dirname.split(os.sep)[1]}/index.html")
                fn.writelines(updated_home_html)