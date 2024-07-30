#!/usr/bin/env python
"""Sophos Firewall Audit

Copyright 2024 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.

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
import logging
from datetime import datetime
import argparse
import os
import sys
import yaml
from pynautobot import api
from sophosfirewall_python.firewallapi import SophosFirewall
from sophos_firewall_audit.auth import get_credential
from sophos_firewall_audit.logging_config import LoggingSetup
from sophos_firewall_audit.audit import run_audit, generate_audit_output
from sophos_firewall_audit.rule_export import export_rules, generate_rule_output

logging_setup = LoggingSetup()
logger = logging.getLogger(__name__)

def nb_graphql_query(query, verify):
    """Query Nautobot using GraphQL returning a list of device names

    Args:
        nb_obj (pynautobot.core.api.Api): PyNautobot object
        query (str): GraphQL query
        verify (bool): Enable/Disable certificate checking

    Returns:
        list: List of dicts [{"hostname": name, "port": port}]
    """
    url = os.environ.get("NAUTOBOT_URL")
    token = os.environ.get("NAUTOBOT_TOKEN")
    nautobot = api(url=url, token=token, verify=verify)
    graphql_response = nautobot.graphql.query(query=query)
    return [{"hostname": firewall["name"], "port": "4444"} for firewall in graphql_response.json["data"]["devices"]]

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

def location_query(environ, locations):
    """Generate GraphQL query

    Args:
        environ (Environment): Jinja2 Environment
        locations (list): List of locations

    Returns:
        str: GraphQL query
    """
    templ = environ.get_template("location_query.j2")
    return templ.render(location_list=locations)

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

def main():

    parser = argparse.ArgumentParser()
    group1 = parser.add_mutually_exclusive_group(required=True)
    group1.add_argument("-i", "--inventory_file", help="Inventory filename")
    group1.add_argument("-n", "--use_nautobot", help="Use Nautobot for inventory", action="store_true")
    parser.add_argument("-q", "--query_file", help="File containing Nautobot GraphQL query")
    parser.add_argument("-d","--disable_verify", help="Disable certificate checking for Nautobot", action="store_false", default=True)
    parser.add_argument("-s", "--settings_file", help="Audit settings YAML file", default="audit_settings.yaml")
    parser.add_argument("-u", "--use_vault", help="Use HashiCorp Vault to retrieve credentials", action="store_true", default=False)
    parser.add_argument("-r", "--rule_export", help="Export rules for offline viewing", action="store_true", default=False)

    args = parser.parse_args()

    if args.use_nautobot and not args.query_file:
        parser.error('--query_file is required when --use_nautobot is specified.')

    
    logging.info("Starting Sophos Firewall audit")

    if args.use_nautobot:
        with open(args.query_file, "r", encoding="utf-8") as fn:
            nb_query = fn.read()
        firewalls = nb_graphql_query(nb_query, args.disable_verify)
        logging.info(f"Using Nautobot inventory with GraphQL query: \n{nb_query}")
    if args.inventory_file:
        with open(args.inventory_file, "r", encoding="utf-8") as fn:
            firewalls = yaml.safe_load(fn)

    if args.use_vault:
        logging.info ("Retrieving credentials from Vault...")
        try:
            os.environ["VAULT_ADDR"]
        except KeyError:
            logging.error("Missing VAULT_ADDR environment variable!")
            sys.exit(1)
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

    dt = datetime.now()
    if not args.rule_export:
        create_dir("results_html_local")
        create_dir("results_html_web")      
        local_dirname = os.path.join("results_html_local", f"audit-results-{dt.strftime('%Y-%m-%d-%H%M%S')}")
        web_dirname = os.path.join("results_html_web", f"audit-results-{dt.strftime('%Y-%m-%d-%H%M%S')}")
        os.mkdir(local_dirname)
        os.mkdir(web_dirname)
    elif args.rule_export:
        logging.info("Rule export flag detected, initiating rule export (audit will be skipped!)")
        create_dir("rule_export_local")
        create_dir("rule_export_web")
        local_dirname = os.path.join("rule_export_local", f"rule-export-{dt.strftime('%Y-%m-%d-%H%M%S')}")
        web_dirname = os.path.join("rule_export_web", f"rule-export-{dt.strftime('%Y-%m-%d-%H%M%S')}")
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
        
        if not args.rule_export:
            status_dict = run_audit(args, fw, firewall, status_dict, local_dirname, web_dirname)
        elif args.rule_export:
            export_rules(fw, firewall, local_dirname, web_dirname)
            logging.info(f"{firewall['hostname']}: Rule export completed successfully!")
    
    if not args.rule_export:
        generate_audit_output(status_dict, local_dirname, web_dirname)
    elif args.rule_export:
        generate_rule_output(firewalls, local_dirname, web_dirname)
    

if __name__ == "__main__":
    main()