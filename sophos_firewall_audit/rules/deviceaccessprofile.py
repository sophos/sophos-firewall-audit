"""Sophos Firewall Audit - deviceaccessprofile.py
 Copyright 2024 Sophos Ltd.  All rights reserved.
 Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
 permissions and limitations under the License.
"""

from sophosfirewall_python.firewallapi import SophosFirewall
from sophos_firewall_audit.utils import html_status, format_diff
from difflib import unified_diff
import logging
import sys

def eval_device_access_profile(fw_obj: SophosFirewall,
                     fw_name: str,
                      settings: dict):
    """Verify Device Access Profiles (System > Profiles > Device Access) 

    Args:
        fw_obj (SophosFirewall): SophosFirewall object
        fw_name (str): Firewall hostname
        settings (dict): Audit settings

    Returns:
        dict: Audit results and output table(s)
    """

    expected_profiles = sorted(settings["profiles"])
    for i in range(1,3):
        try:
            result = fw_obj.get_admin_profile()
        except Exception as err:
            logging.exception(f"Error while retrieving device access profiles for firewall {fw_name}: {err}")
            if i < 3:
                logging.info(f"Retry #{i}")
                continue
            else:
                logging.exception("Unrecoverable error, exiting!")
                sys.exit(1)
        break
    
    profiles = sorted([profile["Name"] for profile in result["Response"]["AdministrationProfile"]
                      if not profile["Name"].startswith("_")])

    result_dict = {
        "profiles": {
            "expected": expected_profiles,
            "actual": profiles
        },
        "pass_ct": 0,
        "fail_ct": 0
    }
    if profiles == expected_profiles:
        result_dict["profiles"]["status"] = "AUDIT_PASS"
        result_dict["pass_ct"] += 1
    else:
        result_dict["profiles"]["status"] = "AUDIT_FAIL"
        result_dict["fail_ct"] += 1
    
    if result_dict["profiles"]["status"] == "AUDIT_FAIL":
        result_dict["audit_result"] = "FAIL"
    else:
        result_dict["audit_result"] = "PASS"
    
    output = []

    if result_dict["profiles"]["status"] == "AUDIT_FAIL":
        diff = unified_diff(sorted(result_dict["profiles"]["expected"]), sorted(result_dict["profiles"]["actual"]), n=100000000)
        actual_output = "\n".join(format_diff(diff))
    else:
        actual_output = "\n".join(result_dict["profiles"]["actual"])

    output.append([
            "Device Access Profiles",
            "System > Profiles > Device Access",
            "profiles",
             "\n".join(result_dict["profiles"]["expected"]),
             actual_output,
             html_status(result_dict["profiles"]["status"])
        ])

    logging.info(f"{fw_name}: Device Access Profiles Result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict