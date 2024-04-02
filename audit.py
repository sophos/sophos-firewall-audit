"""Sophos Firewall Audit

Environment Variables

If using HashiCorp Vault:
VAULT_MOUNT_POINT = HashiCorp Vault Mount Point (ex. kv)
VAULT_SECRET_PATH = HashiCorp Vault Secret path
VAULT_SECRET_KEY = HashiCore Vault Secret Key
ROLEID = HashiCorp Vault Role ID
SECRETID = HashiCorp Vault Secret ID

If not using HashiCorp Vault:
FW_USERNAME = Firewall username
FW_PASSWORD = Firewall password

Optional, for use with Nautobot as inventory:
NAUTOBOT_URL = Nautobot URL
NAUTOBOT_TOKEN = Nautobot API Token
"""
# Patching prettytable to disable escaping
# https://github.com/jazzband/prettytable/issues/40
import html
html.escape = lambda *args, **kwargs: args[0]
from prettytable import PrettyTable
from prettytable import ALL
from pynautobot import api
from sophosfirewall_python.firewallapi import SophosFirewall
from auth import get_credential
import rules
import os
import logging
from datetime import datetime
import json
import argparse
import yaml
from jinja2 import Environment, PackageLoader, Template, select_autoescape
from rich.logging import RichHandler
from rich.highlighter import RegexHighlighter
from rich.theme import Theme
from rich.console import Console



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

def nb_graphql_query(query):
    """Query Nautobot using GraphQL returning a list of device names

    Args:
        nb_obj (pynautobot.core.api.Api): PyNautobot object
        query (str): GraphQL query

    Returns:
        list: List of dicts [{"hostname": name, "port": port}]
    """
    url = os.environ.get("NAUTOBOT_URL")
    token = os.environ.get("NAUTOBOT_TOKEN")
    nautobot = api(url=url, token=token)
    nautobot.http_session.verify=False
    graphql_response = nautobot.graphql.query(query=query)
    return [{"hostname": firewall["name"], "port": "4444"} for firewall in graphql_response.json["data"]["devices"]
            if firewall["device_type"]["_custom_field_data"]["network_os"] == "sfos"]

def device_query(environ, devices):
    """Generate GraphQL query

    Args:
        environ (Environment): Jinja2 Environment
        devices (list): List of devices

    Returns:
        str: GraphQL query
    """
    templ = environ.get_template("device_query.j2")
    return templ.render(device_list=devices)

def site_query(environ, sites):
    """Generate GraphQL query

    Args:
        environ (Environment): Jinja2 Environment
        sites (list): List of sites

    Returns:
        str: GraphQL query
    """
    templ = environ.get_template("site_query.j2")
    return templ.render(site_list=sites)

def region_query(environ, regions):
    """Generate GraphQL query

    Args:
        environ (Environment): Jinja2 Environment
        regions (list): List of regions

    Returns:
        str: GraphQL query
    """
    templ = environ.get_template("region_query.j2")
    return templ.render(region_list=regions)

def all_devices_query(environ):
    """Generate GraphQL query

    Args:
        environ (Environment): Jinja2 Environment

    Returns:
        str: GraphQL query
    """
    templ = environ.get_template("all_devices_query.j2")
    return templ.render()

def create_dir(dirpath):
    try:
        os.mkdir(dirpath)
    except FileExistsError:
        logging.info("Skipping creation of %s because it already exists", dirpath)
    return

if __name__ == '__main__':

    env = Environment(
        loader=PackageLoader("audit"),
        autoescape=select_autoescape()
    )

    parser = argparse.ArgumentParser()
    group1 = parser.add_mutually_exclusive_group()
    group2 = parser.add_mutually_exclusive_group()
    group1.add_argument("-n", "--use_nautobot", help="Use Nautobot for inventory", action="store_true")
    group1.add_argument("-i", "--inventory_file", help="Inventory filename")
    group2.add_argument("-s", "--site_list", help="Comma separated list of Nautobot Sites for selection of devices")
    group2.add_argument("-r", "--region_list", help="Comma separated list of Nautobot Regions for selection of devices")
    group2.add_argument("-d", "--device_list", help="Comma separated list of Nautobot Devices")
    group2.add_argument("-a", "--all_devices", help="All Sophos firewalls in Nautobot", action="store_true")
    parser.add_argument("-f", "--file", help="Audit settings YAML file", default="audit_settings.yaml")
    parser.add_argument("-v", "--use_vault", help="Use HashiCorp Vault to retrieve credentials", action="store_true", default=False)

    args = parser.parse_args()
    logging.info("Starting Sophos Firewall audit")

    if args.use_nautobot:
        if args.device_list:
            device_list = [line.strip() for line in args.device_list.split(",")]
            nb_query = device_query(env, device_list)
        if args.site_list:
            site_list = [line.strip() for line in args.site_list.split(",")]
            nb_query = site_query(env, site_list)
        if args.region_list:
            region_list = [line.strip() for line in args.region_list.split(",")]
            nb_query = region_query(env, region_list)
        if args.all_devices:
            nb_query = all_devices_query(env)
        firewalls = nb_graphql_query(nb_query)
        logging.info(f"Using Nautobot inventory with GraphQL query: \n{nb_query}")
    if args.inventory_file:
        with open(args.inventory_file, "r", encoding="utf-8") as fn:
            firewalls = yaml.safe_load(fn)


    if args.use_vault:
        logging.info ("Retrieving credentials from Vault...")
        fw_password = get_credential(
            mount_point=os.environ['VAULT_MOUNT_POINT'],
            secret_path=os.environ['VAULT_SECRET_PATH'],
            key = os.environ['VAULT_SECRET_KEY']
        )
        logging.info("Successfully retrieved credentials!")
    
    else:
        fw_username = os.environ.get("FW_USERNAME")
        fw_password = os.environ.get("FW_PASSWORD")
        
  
    status_dict = {}


    create_dir("results_html")
    create_dir("docker/results_html")

    dt = datetime.now()
    local_dirname = os.path.join("results_html", f"audit-results-{dt.strftime('%Y-%m-%d-%H%M%S')}")
    web_dirname = os.path.join("docker", "results_html", f"audit-results-{dt.strftime('%Y-%m-%d-%H%M%S')}")
    os.mkdir(local_dirname)
    os.mkdir(web_dirname)

    for firewall in firewalls:
        fw = SophosFirewall(
            username=os.environ['VAULT_SECRET_KEY'] if args.use_vault else fw_username,
            password=fw_password,
            hostname=firewall['hostname'],
            port=firewall['port'],
            verify=False
        )

        try:
            fw.login()
        except Exception as Error:
            logging.error(f"Error connecting to firewall {firewall['hostname']}: {Error}")
            continue

        with open(args.file, "r") as fn:
            templ = Template(source=fn.read())
            rendered = templ.render({"firewall_hostname": fw.hostname.split(".")[0]})
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
        result_html = template.render(firewall_name=firewall_name, table=table.get_html_string(format=True, escape_data=False))

        for dirname in [local_dirname, web_dirname]:
            with open (f"{dirname}/{firewall_name}.html", "w", encoding="utf-8") as fn:
                fn.write(result_html)

            with open(f"{dirname}/{firewall['hostname']}.json", "w", encoding="utf-8") as fn:
                fn.write(json.dumps(results, indent=4))

    template = env.get_template("index.j2")

    firewall_list = [firewall['hostname'] for firewall in firewalls]

    with open("results.json", "w", encoding="utf-8") as fn:
        fn.write(json.dumps(status_dict))

    for dirname in [local_dirname, web_dirname]:
        index_html = template.render(status_dict=status_dict, dirname=dirname)

        with open(f"{dirname}/index.html", "w", encoding="utf-8") as fn:
            fn.write(index_html)

        if "docker" in dirname:
            try:
                with open(os.path.join("docker", "results_html", "index.html"), "r", encoding="utf-8") as fn:
                    home_html = fn.readlines()
            except FileNotFoundError:
                with open(os.path.join("templates", "home_index.j2"), "r") as fn:
                    home_html = fn.readlines()
                with open(os.path.join("docker", "results_html", "index.html"), "w", encoding="utf-8") as fn:
                    fn.writelines(home_html)
        else:
            try:
                with open(os.path.join("results_html", "index.html"), "r", encoding="utf-8") as fn:
                    home_html = fn.readlines()
            except FileNotFoundError:
                with open(os.path.join("templates", "home_index.j2"), "r") as fn:
                    home_html = fn.readlines()
                with open(os.path.join("results_html", "index.html"), "w", encoding="utf-8") as fn:
                    fn.writelines(home_html)                  

        updated_home_html = []

        for line in home_html:
            if "<h1>Firewall Audit</h1>" in line:
                updated_home_html.append(line)
                if "docker" in dirname:
                    updated_home_html.append(
                        f'<a style="text-align: left;" href="/{dirname.split("/")[2]}/index.html">{dirname.split("/")[2]}</a><br/>\n'
                    )
                    
                else:
                   updated_home_html.append(
                        f'<a style="text-align: left;" href="file:{dirname.split("/")[1]}/index.html">{dirname.split("/")[1]}</a><br/>\n'
                    )
                    
            else:
                updated_home_html.append(line)

        if "docker" in dirname:
            with open(os.path.join("docker", "results_html", "index.html"), "w", encoding="utf-8") as fn:
                fn.writelines(updated_home_html)
        else:
            with open(os.path.join("results_html", "index.html"), "w", encoding="utf-8") as fn:
                fn.writelines(updated_home_html)
        