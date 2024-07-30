
""" Sophos Firewall Audit - remediate.py
 
 Copyright 2024 Sophos Ltd.  All rights reserved.
 Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
 permissions and limitations under the License.
 """

import os
import logging
import glob
import json
import pprint
from argparse import ArgumentParser
from rich.logging import RichHandler
from rich.highlighter import RegexHighlighter
from rich.theme import Theme
from rich.console import Console
from auth import get_credential
from sophosfirewall_python.firewallapi import SophosFirewall

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
parser = ArgumentParser()
parser.add_argument("--results_dir", required=True, help="Directory containing audit results")
args = parser.parse_args()


def backup(fw_obj, hostname, settings):
    """Update Backup configuration (System > Backup & firmware)

    Args:
        fw_obj (SophosFirewall): SophosFirewall object
        hostname (str): Firewall hostname
        settings (dict): Dict containing the backup settings to be configured

    Returns:
        Requests.response: API response object
    """
    logging.info(f"{hostname}: Begin updating Backup settings")
    resp = fw_obj.update_backup(backup_params=settings, debug=False)
    code = resp["Response"]["BackupRestore"]["Status"]["@code"]
    message = resp["Response"]["BackupRestore"]["Status"]["#text"]
    logging.info(f"{hostname}: {code} {message}")
    return resp

def access_acl_hostgroups(fw_obj, hostname, settings):
    pass

def access_acl_services(fw_obj, hostname, settings):
    pass

def device_access_profiles(fw_obj, hostname, settings):
    pass

def admin_services(fw_obj, hostname, settings):
    pass

def authen_servers(fw_obj, hostname, settings):
    pass

def atp(fw_obj, hostname, settings):
    pass

def ips_policies(fw_obj, hostname, settings):
    pass

def host_groups(fw_obj, hostname, settings):
    pass

def syslog(fw_obj, hostname, settings):
    pass

def notifications(fw_obj, hostname, settings):
    pass

def notification_list(fw_obj, hostname, settings):
    pass

def certificate(fw_obj, hostname, settings):
    pass

def login_security(fw_obj, hostname, settings):
    pass

def dns_servers(fw_obj, hostname, settings):
    pass

def snmpv3(fw_obj, hostname, settings):
    pass

function_dict = {
    "backup": backup,
    "acl_hostgroups": access_acl_hostgroups,
    "acl_services": access_acl_services,
    "profiles": device_access_profiles,
    "services": admin_services,
    "servers": authen_servers,
    "atp": atp,
    "policies": ips_policies,
    "hostgroups": host_groups,
    "syslog": syslog,
    "notifications": notifications,
    "notification_list": notification_list,
    "certificate": certificate,
    "loginsecurity": login_security,
    "servers": dns_servers,
    "snmpv3": snmpv3
}

if __name__ == "__main__":

    AUDIT_DIR = args.results_dir

    logging.info(f"Begin firewall remediation using audit results {AUDIT_DIR}")

    for results_file in glob.glob(f"{AUDIT_DIR}/*.json"):
        hostname = results_file.split("/")[1].replace(".json", "")       
        logging.info ("Retrieving credentials from Vault...")
        fw_password = get_credential(
            mount_point=os.environ['VAULT_MOUNT_POINT'],
            secret_path=os.environ['VAULT_SECRET_PATH'],
            key = os.environ['VAULT_USERNAME']
        )
        logging.info("Successfully retrieved credentials!")

        fw = SophosFirewall(
            username=os.environ['VAULT_USERNAME'],
            password=fw_password,
            hostname=hostname,
            port=4444
        )
        logging.info(f"Remediation beginning for firewall: {hostname}")

        with open(results_file, "r", encoding="utf-8") as fn:
            results = json.loads(fn.read())

        failed_list = []
        for result in results:
            failed_dict = {}
            for key in result['result']:
                if not key == "audit_result" and not key == "output":
                    if result['result']['audit_result'] == "FAIL":
                        failed_dict["test_name"] = key
                        failed_dict["expected"] = result["result"][key]["expected"]
                        failed_list.append(failed_dict)
                        logging.info(f"{hostname}: Processing for failed audit {key}")
                        logging.info(f"{hostname}: {key} expected: \n{pprint.PrettyPrinter(width=20).pformat(result['result'][key]['expected'])}")
                        logging.info(f"{hostname}: {key} actual: \n{pprint.PrettyPrinter(width=20).pformat(result['result'][key]['actual'])}")

        for failed in failed_list:
            logging.info(f"{hostname}: Updating {failed['test_name']} with settings\n {pprint.PrettyPrinter(width=20).pformat(failed['expected'])}")
            resp = function_dict[failed["test_name"]](fw, hostname, failed["expected"])

