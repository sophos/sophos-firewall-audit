"""Sophos Firewall Audit - backup.py
 Copyright 2024 Sophos Ltd.  All rights reserved.
 Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
 permissions and limitations under the License.
"""

from sophosfirewall_python.firewallapi import SophosFirewall, SophosFirewallZeroRecords
from requests import RequestException
from sophos_firewall_audit.utils import html_yellow, html_status
import logging
import sys

def eval_backup(fw_obj: SophosFirewall,
                     fw_name: str,
                      settings: dict):
    """Verify Scheduled Backup settings (System > Backup & firmware > Backup) 

    Args:
        fw_obj (SophosFirewall): SophosFirewall object
        fw_name (str): Firewall hostname
        settings (dict): Audit settings

    Returns:
        dict: Audit results and output table(s)
    """

    expected_settings = settings["scheduled_backup"]

    for i in range(1,3):
        try:
            result = fw_obj.get_backup()
        except RequestException as err:
            logging.exception(f"Error while retrieving Backup settings for firewall {fw_name}: {err}")
            if i < 3:
                logging.info(f"Retry #{i}")
                continue
            else:
                logging.exception("Unrecoverable error, exiting!")
                sys.exit(1)
        except SophosFirewallZeroRecords:
            result = None
            break
        break
    
    if result:
        actual_settings = result["Response"]["BackupRestore"]["ScheduleBackup"]
    else:
        actual_settings = {}

    result_dict = {
        "backup": {
            "expected": expected_settings,
            "actual": actual_settings,
            "status": "AUDIT_PASS"
        },
        "pass_ct": 0,
        "fail_ct": 0
    }
    result_dict["audit_result"] = "PASS"

    expected_list = []
    actual_list = []
    for setting in expected_settings.keys():
        if actual_settings.get(setting) == 'None':
            actual_settings[setting] = None
        expected_list.append(f"{setting}: {expected_settings[setting]}")
        
        if  str(expected_settings[setting]).lower() != str(actual_settings.get(setting)).lower():
            actual_list.append(f"{setting}: {html_yellow(actual_settings.get(setting))}")
            result_dict["backup"]["status"] = "AUDIT_FAIL"
            result_dict["audit_result"] = "FAIL"
        else:
            actual_list.append(f"{setting}: {actual_settings.get(setting)}")
    if result_dict["audit_result"] == "PASS":
        result_dict["pass_ct"] += 1
    else:
        result_dict["fail_ct"] += 1
     
    output = []

    output.append([
            "Scheduled Backup",
            "System > Backup & firmware > Backup & restore",
            "backup",
             "\n".join(expected_list),
             "\n".join(actual_list),
             html_status(result_dict["backup"]["status"])
        ])

    logging.info(f"{fw_name}: Scheduled Backup Result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict