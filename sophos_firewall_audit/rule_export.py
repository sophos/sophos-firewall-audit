"""Sophos Firewall Audit

Copyright 2024 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
"""
import os
import logging
from sophos_firewall_audit.logging_config import LoggingSetup
from jinja2 import Environment, PackageLoader, Template, select_autoescape
from prettytable import PrettyTable
from prettytable import ALL

logging_setup = LoggingSetup()
logger = logging.getLogger(__name__)

env = Environment(
    loader=PackageLoader("sophos_firewall_audit"),
    autoescape=select_autoescape()
)

def format_object(policy, parent, child):
    if parent in policy:
        if isinstance(policy[parent][child], str):
            return policy[parent][child]
        elif isinstance(policy[parent][child], list):
            return '\n'.join(policy[parent][child])
    else:
        return "Any"

def process_rules(rules):
    output = []
    for rule in rules["Response"]["FirewallRule"]:
        if rule["PolicyType"] == "Network":
            output.append(
                [
                    rule["Name"],
                    rule["Description"],
                    rule["Status"],
                    rule["NetworkPolicy"]["Action"],
                    format_object(rule["NetworkPolicy"], "SourceNetworks", "Network"),
                    format_object(rule["NetworkPolicy"], "SourceZones", "Zone"),
                    format_object(rule["NetworkPolicy"], "DestinationNetworks", "Network"),
                    format_object(rule["NetworkPolicy"], "DestinationZones", "Zone"),
                    format_object(rule["NetworkPolicy"], "Services", "Service"),
                    rule["NetworkPolicy"]["LogTraffic"],
                    rule["NetworkPolicy"]["Schedule"]
                ]
            )
    return output


def export_rules(fw_obj, firewall, local_dirname, web_dirname):

    firewall_name = firewall["hostname"]
    logging.info(f"{firewall_name}: Begin rule export...")
    rules = fw_obj.get_fw_rule()
    table = PrettyTable()
    table.hrules = ALL
    table.field_names = ["Name", "Description", "Status", "Action", "Src Network", "Src Zone", "Dst Network", "Dst Zone", "Service", "Log", "Schedule"]
    output = process_rules(rules)
    table.add_rows(output)
    table.valign = "m"
    table.align["Expected"] = "l"
    table.align["Actual"] = "l"

    template = env.get_template("results.j2")
    result_html = template.render(firewall_name=firewall_name,
                                  table=table.get_html_string(format=True, escape_data=False),
                                  title="Firewall Ruleset")
    for dirname in [local_dirname, web_dirname]:
        with open (f"{os.path.join(dirname, firewall_name)}.html", "w", encoding="utf-8") as fn:
            fn.write(result_html)    

def generate_rule_output(firewalls, local_dirname, web_dirname):
    template = env.get_template("rules_index.j2")

    firewall_list = [firewall['hostname'] for firewall in firewalls]

    for dirname in [local_dirname, web_dirname]:
        index_html = template.render(firewall_list=firewall_list, dirname=dirname, title="Firewall Rule Export")

        with open(os.path.join(dirname, 'index.html'), "w", encoding="utf-8") as fn:
            fn.write(index_html)

        home_template = env.get_template("home.j2")

        if "web" in dirname:
            try:
                with open(os.path.join("rule_export_web", "index.html"), "r", encoding="utf-8") as fn:
                    home_html = fn.readlines()
            except FileNotFoundError:
                home_html = home_template.render(title="Firewall Rule Export").splitlines(True)
                with open(os.path.join("rule_export_web", "index.html"), "w", encoding="utf-8") as fn:
                    fn.writelines(home_html)
        else:
            try:
                with open(os.path.join("rule_export_local", "index.html"), "r", encoding="utf-8") as fn:
                    home_html = fn.readlines()
            except FileNotFoundError:
                home_html = home_template.render(title="Firewall Rule Export").splitlines(True)
                with open(os.path.join("rule_export_local", "index.html"), "w", encoding="utf-8") as fn:
                    fn.writelines(home_html)                  

        updated_home_html = []

        for line in home_html:
            if "<h1>Firewall Rule Export</h1>" in line:
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
            with open(os.path.join("rule_export_web", "index.html"), "w", encoding="utf-8") as fn:
                fn.writelines(updated_home_html)
        else:
            with open(os.path.join("rule_export_local", "index.html"), "w", encoding="utf-8") as fn:
                logging.info(f"Rule export results: rule_export_local{os.sep}{dirname.split(os.sep)[1]}/index.html")
                fn.writelines(updated_home_html)

