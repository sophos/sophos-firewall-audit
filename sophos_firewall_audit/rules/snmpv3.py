"""Sophos Firewall Audit - snmpv3.py
 Copyright 2024 Sophos Ltd.  All rights reserved.
 Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
 permissions and limitations under the License.
"""
from sophosfirewall_python.firewallapi import SophosFirewall, SophosFirewallZeroRecords
from sophos_firewall_audit.utils import html_status, format_diff
from difflib import unified_diff
import logging
import sys

def eval_snmpv3(fw_obj: SophosFirewall,
                     fw_name: str,
                      settings: dict):
    """Verify SNMPv3 (System > Administration > SNMP) 

    Args:
        fw_obj (SophosFirewall): SophosFirewall object
        fw_name (str): Firewall hostname
        settings (dict): Audit settings

    Returns:
        dict: Audit results and output table(s)
    """

    expected = settings["snmpv3"]
    
    for i in range(1,3):
        try:
            result = fw_obj.get_snmpv3_user()
        except SophosFirewallZeroRecords:
            result = None
            break
        except Exception as err:
            logging.exception(f"Error while retrieving authentication servers for firewall {fw_name}: {err}")
            if i < 3:
                logging.info(f"Retry #{i}")
                continue
            else:
                logging.exception("Unrecoverable error, exiting!")
                sys.exit(1)
        break

    if result:
        actual = result["Response"]["SNMPv3User"]
    else:
        actual = {}

    result_dict = {
        "snmpv3": {
            "expected": expected,
            "actual": actual,
        },
        "audit_result": "PASS",
        "pass_ct": 0,
        "fail_ct": 0
    }
    
    output = []
    for key in expected:
        status = "AUDIT_PASS"
        if key in actual:
            if not expected[key] == actual[key]:
                status = "AUDIT_FAIL"
                result_dict["audit_result"] = "FAIL"
                result_dict["fail_ct"] += 1
            else:
                result_dict["pass_ct"] += 1
        else:
            actual[key] = "None"
            status = "AUDIT_FAIL"
            result_dict["audit_result"] = "FAIL"
            result_dict["fail_ct"] += 1

        if key == "AuthorizedHosts" and not actual.get(key) == "None" and status == "AUDIT_FAIL":
            actual_output = '\n'.join(format_diff(unified_diff(sorted(expected[key]), sorted(actual.get(key)), n=1000000000)))
        elif key == "AuthorizedHosts" and not actual.get(key) == "None" and status == "AUDIT_PASS":
            actual_output = '\n'.join(actual.get(key))
        else:
            actual_output = actual.get(key)

        output.append([
                "SNMPv3",
                "System > Administration > SNMP",
                key,
                '\n'.join(expected[key]) if key == "AuthorizedHosts" else expected[key],
                actual_output,
                html_status(status)
            ])

    logging.info(f"{fw_name}: SNMPv3 Result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict