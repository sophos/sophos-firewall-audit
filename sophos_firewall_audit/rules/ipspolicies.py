"""Sophos Firewall Audit - ipspolicies.py
 Copyright 2024 Sophos Ltd.  All rights reserved.
 Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
 permissions and limitations under the License.
"""

from sophosfirewall_python.firewallapi import SophosFirewall
from sophos_firewall_audit.utils import html_status, format_diff, html_yellow
from difflib import unified_diff
import logging
import sys

def eval_ips_policies(fw_obj: SophosFirewall,
                     fw_name: str,
                      settings: dict):
    """Verify IPS Policies (Protect > Intrusion prevention > IPS policies) 

    Args:
        fw_obj (SophosFirewall): SophosFirewall object
        fw_name (str): Firewall hostname
        settings (dict): Audit settings

    Returns:
        dict: Audit results and output table(s)
    """

    expected_policies = sorted(settings["policies"])
    expected_status = settings["status"]

    for i in range(1,3):
        try:
            result = fw_obj.get_ips_policy()
        except Exception as err:
            logging.exception(f"Error while retrieving IPS policies for firewall {fw_name}: {err}")
            if i < 3:
                logging.info(f"Retry #{i}")
                continue
            else:
                logging.exception("Unrecoverable error, exiting!")
                sys.exit(1)
        break
    
    actual_policies = sorted([policy["Name"] for policy in result["Response"]["IPSPolicy"]])

    for i in range(1,3):
        try:
            result = fw_obj.get_tag("IPSSwitch")
        except Exception as err:
            logging.exception(f"Error while retrieving IPS status for firewall {fw_name}: {err}")
            if i < 3:
                logging.info(f"Retry #{i}")
                continue
            else:
                logging.exception("Unrecoverable error, exiting!")
                sys.exit(1)
        break

    actual_status = result["Response"]["IPSSwitch"]["Status"]

    result_dict = {
        "policies": {
            "expected": expected_policies,
            "actual": actual_policies
        },
        "ips_status": {
            "expected": expected_status,
            "actual": actual_status
        },
        "audit_result": "PASS",
        "pass_ct": 0,
        "fail_ct": 0
    }
    if actual_policies == expected_policies:
        result_dict["policies"]["status"] = "AUDIT_PASS"
        result_dict["pass_ct"] += 1
    else:
        result_dict["policies"]["status"] = "AUDIT_FAIL"
        result_dict["fail_ct"] += 1
        result_dict["audit_result"] = "FAIL"

    if actual_status == expected_status:
        result_dict["ips_status"]["status"] = "AUDIT_PASS"
        result_dict["pass_ct"] += 1
    else:
        result_dict["ips_status"]["status"] = "AUDIT_FAIL"
        result_dict["fail_ct"] += 1
        result_dict["audit_result"] = "FAIL"
    
    output = []

    if result_dict["ips_status"]["status"] == "AUDIT_FAIL":
        actual_output = html_yellow(result_dict["ips_status"]["actual"])
    else:
        actual_output = result_dict["ips_status"]["actual"]

    output.append([
            "IPS Status",
            "(Protect > Intrusion prevention > IPS policies",
            "enabled/disabled",
            result_dict["ips_status"]["expected"],
            actual_output,
            html_status(result_dict["ips_status"]["status"])
        ])

    if result_dict["policies"]["status"] == "AUDIT_FAIL":
        diff = unified_diff(sorted(result_dict["policies"]["expected"]), 
                                   sorted(result_dict["policies"]["actual"]), n=100000000)
        actual_output = "\n".join(format_diff(diff))
    else:
        actual_output = "\n".join(result_dict["policies"]["actual"])

    output.append([
            "IPS Policies",
            "(Protect > Intrusion prevention > IPS policies",
            "ips policies",
            "\n".join(result_dict["policies"]["expected"]),
            actual_output,
            html_status(result_dict["policies"]["status"])
        ])

    logging.info(f"{fw_name}: IPS Policies Result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict