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

# GUI "Match known users" rules are PolicyType User and live under UserPolicy.
# Network rules stay under NetworkPolicy. Both share the same traffic fields.
_POLICY_BODIES = ("NetworkPolicy", "UserPolicy")
_EXPORTABLE_TYPES = {"Network", "User"}


def format_object(policy, parent, child):
    if not isinstance(policy, dict) or parent not in policy or policy[parent] in (None, ""):
        return "Any"
    node = policy[parent]
    if isinstance(node, str):
        return node
    if isinstance(node, list):
        return "\n".join(str(item) for item in node)
    if not isinstance(node, dict) or child not in node or node[child] in (None, ""):
        return "Any"
    value = node[child]
    if isinstance(value, list):
        return "\n".join(str(item) for item in value)
    return str(value)


def _as_rule_list(rules):
    """xmltodict returns one FirewallRule as a dict and many as a list."""
    ruleset = {}
    if isinstance(rules, dict):
        ruleset = rules.get("Response", {}).get("FirewallRule", [])
    if isinstance(ruleset, dict):
        return [ruleset]
    if isinstance(ruleset, list):
        return [rule for rule in ruleset if isinstance(rule, dict)]
    return []


def _policy_body(rule):
    for key in _POLICY_BODIES:
        body = rule.get(key)
        if isinstance(body, dict):
            return body
    # Some API responses lift UserPolicy fields onto the rule itself.
    if rule.get("PolicyType") in _EXPORTABLE_TYPES and "Action" in rule:
        return rule
    return None


def _member_names(value):
    if value in (None, ""):
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        names = []
        for item in value:
            names.extend(_member_names(item))
        return names
    if isinstance(value, dict):
        names = []
        for child in ("Member", "User", "Username", "Group", "Name"):
            if child in value:
                names.extend(_member_names(value[child]))
        return names
    return [str(value)]


def format_identity(policy):
    """Describe Match known users / captive portal on a UserPolicy."""
    if not isinstance(policy, dict):
        return ""
    parts = []
    match = policy.get("MatchIdentity")
    if isinstance(match, str) and match.lower() == "enable":
        parts.append("Match known users")
    members = []
    for key in ("Member", "Members", "User", "Users", "Identity"):
        if key in policy:
            members.extend(_member_names(policy[key]))
    seen = []
    for name in members:
        if name not in seen:
            seen.append(name)
    if seen:
        parts.append("\n".join(seen))
    portal = policy.get("ShowCaptivePortal")
    if isinstance(portal, str) and portal.lower() == "enable":
        parts.append("Captive portal")
    return "\n".join(parts)


def process_rules(rules):
    output = []
    for rule in _as_rule_list(rules):
        if rule.get("PolicyType") not in _EXPORTABLE_TYPES:
            continue
        policy = _policy_body(rule)
        if policy is None:
            continue
        output.append(
            [
                rule.get("Name", ""),
                rule.get("Description", ""),
                rule.get("Status", ""),
                policy.get("Action", ""),
                format_object(policy, "SourceNetworks", "Network"),
                format_object(policy, "SourceZones", "Zone"),
                format_object(policy, "DestinationNetworks", "Network"),
                format_object(policy, "DestinationZones", "Zone"),
                format_object(policy, "Services", "Service"),
                policy.get("LogTraffic", ""),
                policy.get("Schedule", ""),
                format_identity(policy),
            ]
        )
    return output


def export_rules(fw_obj, firewall, local_dirname, web_dirname):

    firewall_name = firewall["hostname"]
    logging.info(f"{firewall_name}: Begin rule export...")
    rules = fw_obj.get_fw_rule()
    table = PrettyTable()
    table.hrules = ALL
    table.field_names = ["Name", "Description", "Status", "Action", "Src Network", "Src Zone", "Dst Network", "Dst Zone", "Service", "Log", "Schedule", "Identity"]
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

