"""Sophos Firewall Audit - smtpprotection.py
 Copyright 2024 Sophos Ltd.  All rights reserved.
 Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
 permissions and limitations under the License.
"""
from sophosfirewall_python.firewallapi import SophosFirewall
from sophos_firewall_audit.utils import html_status
from sophos_firewall_audit.utils import html_yellow
import logging
import sys

def eval_smtp_protection(fw_obj: SophosFirewall,
                     fw_name: str,
                      settings: dict):
    """Verify SMTP Protection Settings (Protect > Email > General Settings) 

    Args:
        fw_obj (SophosFirewall): SophosFirewall object
        fw_name (str): Firewall hostname
        settings (dict): Audit settings

    Returns:
        dict: Audit results and output table(s)
    """

    expected = settings["smtp_protect"]["mta_mode"]

    for i in range(1,3):
        try:
            result = fw_obj.get_tag("SMTPDeploymentMode")
        except Exception as err:
            logging.exception(f"Error while retrieving SMTP Deployment Mode configuration for firewall {fw_name}: {err}")
            if i < 3:
                logging.info(f"Retry #{i}")
                continue
            else:
                logging.exception("Unrecoverable error, exiting!")
                sys.exit(1)
        break
    
    actual = result["Response"]["SMTPDeploymentMode"]["MTAMode"]

    result_dict = {
        "smtp_protect": {
            "expected": expected,
            "actual": actual
        },
        "pass_ct": 0,
        "fail_ct": 0
    }
    if actual == expected:
        result_dict["smtp_protect"]["status"] = "AUDIT_PASS"
        result_dict["pass_ct"] += 1
    else:
        result_dict["smtp_protect"]["status"] = "AUDIT_FAIL"
        result_dict["fail_ct"] += 1
    
    if result_dict["smtp_protect"]["status"] == "AUDIT_FAIL":
        result_dict["audit_result"] = "FAIL"
    else:
        result_dict["audit_result"] = "PASS"
    
    output = []

    output.append([
            "SMTP Protection",
            "Protect > Email > General Settings",
            "MTA deployment mode",
             result_dict["smtp_protect"]["expected"],
             html_yellow(result_dict["smtp_protect"]["actual"]) if result_dict["smtp_protect"]["status"] == "AUDIT_FAIL"
               else result_dict["smtp_protect"]["actual"],
             html_status(result_dict["smtp_protect"]["status"])
        ])
    

    logging.info(f"{fw_name}: SMTP MTA Deployment Mode result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict