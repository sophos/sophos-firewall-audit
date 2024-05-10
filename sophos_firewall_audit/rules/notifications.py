"""Sophos Firewall Audit - notifications.py
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

def eval_notifications(fw_obj: SophosFirewall,
                     fw_name: str,
                      settings: dict):
    """Verify Notification settings (System > Administration > Notification settings) 

    Args:
        fw_obj (SophosFirewall): SophosFirewall object
        fw_name (str): Firewall hostname
        settings (dict): Audit settings

    Returns:
        dict: Audit results and output table(s)
    """

    expected_settings = settings["notifications"]
    for i in range(1,3):
        try:
            result = fw_obj.get_notification()
        except Exception as err:
            logging.exception(f"Error while retrieving notification settings for firewall {fw_name}: {err}")
            if i < 3:
                logging.info(f"Retry #{i}")
                continue
            else:
                logging.exception("Unrecoverable error, exiting!")
                sys.exit(1)
        break

    actual_settings = result["Response"]["Notification"]

    result_dict = {
        "notifications": {
            "expected": expected_settings,
            "actual": actual_settings,
            "status": "AUDIT_PASS"
        },
        "pass_ct": 0,
        "fail_ct": 0,
        "audit_result": "PASS"
    }

    expected_list = []
    actual_list = []
    for setting in expected_settings.keys():
        expected_list.append(f"{setting}: {expected_settings[setting]}")
        if not expected_settings[setting] == actual_settings[setting]:
            actual_list.append(f"{setting}: {html_yellow(actual_settings[setting])}")
            result_dict["notifications"]["status"] = "AUDIT_FAIL"
            result_dict["audit_result"] = "FAIL"
            # print(f"expected_settings: {setting}: {expected_settings[setting]}")
            # print(f"actual_settings: {setting}: {actual_settings[setting]}")
        else:
            actual_list.append(f"{setting}: {actual_settings[setting]}")
    if result_dict["audit_result"] == "PASS":
        result_dict["pass_ct"] += 1
    else:
        result_dict["fail_ct"] += 1
    output = []

    output.append([
            "Notification Settings",
            "System > Administration > Notification settings",
            "notification settings",
             "\n".join(expected_list),
             "\n".join(actual_list),
             html_status(result_dict["notifications"]["status"])
        ])

    logging.info(f"{fw_name}: Notification Settings Result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict