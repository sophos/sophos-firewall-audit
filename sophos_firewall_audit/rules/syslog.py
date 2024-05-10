"""Sophos Firewall Audit - syslog.py
 Copyright 2024 Sophos Ltd.  All rights reserved.
 Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
 permissions and limitations under the License.
"""

from sophosfirewall_python.firewallapi import SophosFirewall
from sophos_firewall_audit.utils import html_yellow, html_status
import logging
import sys

def eval_syslog(fw_obj: SophosFirewall,
                     fw_name: str,
                      settings: dict):
    """Verify Syslog settings (Configure > System services > Log settings) 

    Args:
        fw_obj (SophosFirewall): SophosFirewall object
        fw_name (str): Firewall hostname
        settings (dict): Audit settings

    Returns:
        dict: Audit results and output table(s)
    """
    output = []

    for i in range(1,3):
        try:
            result = fw_obj.get_syslog_server()
        except Exception as err:
            logging.exception(f"Error while retrieving Syslog settings for firewall {fw_name}: {err}")
            if i < 3:
                logging.info(f"Retry #{i}")
                continue
            else:
                logging.exception("Unrecoverable error, exiting!")
                sys.exit(1)
        break

    actual_settings = {}
    for settings_group in result["Response"]["SyslogServers"]:
        actual_settings[settings_group["Name"]] = settings_group["LogSettings"]

    expected_settings = settings

    results = []
    for settings_container in expected_settings:
        container_name = settings_container['name']
    
        settings_dict = {}
        for settings_category in settings_container['LogSettings']:
            if not settings_category in settings_dict:
                settings_dict[settings_category] = {}
            for setting in settings_container['LogSettings'][settings_category]:
                settings_dict[settings_category][setting] = {}
                settings_dict[settings_category][setting]["Name"] = container_name
                settings_dict[settings_category][setting]["Expected"] = settings_container['LogSettings'][settings_category][setting]
                if container_name in actual_settings:
                    settings_dict[settings_category][setting]["Actual"] = actual_settings[container_name][settings_category][setting]
                else:
                    settings_dict[settings_category][setting]["Actual"] = f"{container_name} not configured!"
        results.append(settings_dict)

    result_dict = {
        "audit_result": "PASS",
        "pass_ct": 0,
        "fail_ct": 0,
        "syslog": {
            "expected": expected_settings,
            "actual": actual_settings
            } 
        }
    for result in results:
        for category in result.keys():
            category_status = "AUDIT_PASS"
            category_expected = []
            category_actual = []
            for setting in result[category].keys():
                category_expected.append(f"{setting}: {result[category][setting]['Expected']}")
                
                settings_type = result[category][setting]["Name"]
                if not result[category][setting]['Expected'] == result[category][setting]['Actual']:
                    category_actual.append(f"{setting}: {html_yellow(result[category][setting]['Actual'])}")
                    category_status = "AUDIT_FAIL"
                    result_dict["audit_result"] = "FAIL"
                else:
                    category_actual.append(f"{setting}: {result[category][setting]['Actual']}")
            if category_status == "AUDIT_PASS":
                result_dict["pass_ct"] += 1
            else:
                result_dict["fail_ct"] += 1
            output.append([
                "Syslog",
                "Configure > System services > Log settings",
                f"{settings_type}\n{category}",
                "\n".join(category_expected),
                "\n".join(category_actual),
                html_status(category_status)
            ])

    logging.info(f"{fw_name}: Syslog Result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict