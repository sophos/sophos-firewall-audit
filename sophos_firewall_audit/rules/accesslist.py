"""Sophos Firewall Audit - accesslist.py
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
from requests.exceptions import RequestException
import logging
import sys

def eval_access_list(fw_obj: SophosFirewall,
                     fw_name: str,
                      settings: dict):
    """Verify Local service ACL exception rule (System > Administration > Device Access > Local service ACL exception) 

    Args:
        fw_obj (SophosFirewall): SophosFirewall object
        fw_name (str): Firewall hostname
        settings (dict): Audit settings

    Returns:
        dict: Audit results and output table(s)
    """

    expected_hostgroups = sorted(settings["hostgroups"])
    expected_services = sorted(settings["services"])

    for i in range(1,4):
        try:
            acl_result = fw_obj.get_acl_rule()
        except RequestException as err:
            logging.exception(f"Error while retrieving access list for firewall {fw_name}: {err}")
            if i < 3:
                logging.info(f"Retry #{i}")
                continue
            elif i == 3:
                logging.exception("Unrecoverable error, exiting!")
                sys.exit(1)
        except SophosFirewallZeroRecords:
            acl_result = None
            break
        break
    
    if acl_result:
        if isinstance(acl_result["Response"]["LocalServiceACL"], dict):
            hostgroups = sorted(list(set(acl_result["Response"]["LocalServiceACL"]["Hosts"]["Host"])))
            services = sorted(list(set(acl_result["Response"]["LocalServiceACL"]["Services"]["Service"])))

        if isinstance(acl_result["Response"]["LocalServiceACL"], list):
            hostgroups = []
            services = []
            for acl in acl_result["Response"]["LocalServiceACL"]:
                if "Hosts" in acl:
                    if isinstance(acl["Hosts"]["Host"], list):
                        for host in acl["Hosts"]["Host"]:
                            hostgroups.append(host)
                    else:
                        hostgroups.append(acl["Hosts"]["Host"])
                if isinstance(acl["Services"]["Service"], list):
                    for service in acl["Services"]["Service"]:
                        services.append(service)
                else:
                    services.append(acl["Services"]["Service"])
                hostgroups = sorted(list(set(hostgroups)))
                services = sorted(list(set(services)))
    else:
        hostgroups = []
        services = []

    result_dict = {
        "acl_hostgroups": {
            "expected": expected_hostgroups,
            "actual": hostgroups
        },
        "acl_services": {
            "expected": expected_services,
            "actual": services
        },
        "pass_ct": 0,
        "fail_ct": 0
    }
    if hostgroups == expected_hostgroups:
        result_dict["acl_hostgroups"]["status"] = "AUDIT_PASS"
        result_dict["pass_ct"] += 1
    else:
        result_dict["acl_hostgroups"]["status"] = "AUDIT_FAIL"
        result_dict["fail_ct"] += 1

    if services == expected_services:
        result_dict["acl_services"]["status"] = "AUDIT_PASS"
        result_dict["pass_ct"] += 1
    else:
        result_dict["acl_services"]["status"] = "AUDIT_FAIL"
        result_dict["fail_ct"] += 1
    
    if result_dict["acl_hostgroups"]["status"] == "AUDIT_FAIL" or result_dict["acl_services"]["status"] == "AUDIT_FAIL":
        result_dict["audit_result"] = "FAIL"
    else:
        result_dict["audit_result"] = "PASS"
   
    output = []

    if result_dict["acl_hostgroups"]["status"] == 'AUDIT_FAIL':
        diff = unified_diff(result_dict["acl_hostgroups"]["expected"], result_dict["acl_hostgroups"]["actual"], n=100000000)
        actual_output = "\n".join(format_diff(diff))
    else:
        actual_output = "\n".join(result_dict["acl_hostgroups"]["actual"])

    output.append([
            "Access ACL",
            "System > Administration > Device Access > \nLocal service ACL exception",
            "host groups",
             "\n".join(result_dict["acl_hostgroups"]["expected"]),
             actual_output,
             html_status(result_dict["acl_hostgroups"]["status"])
        ])

    if result_dict["acl_services"]["status"] == "AUDIT_FAIL":
        diff = unified_diff(result_dict["acl_services"]["expected"], result_dict["acl_services"]["actual"], n=100000000)
        actual_output = "\n".join(format_diff(diff))
    else:
        actual_output = "\n".join(result_dict["acl_services"]["actual"])

    output.append([
        "Access ACL",
        "System > Administration > Device Access > \nLocal service ACL exception",
        "services",
            "\n".join(result_dict["acl_services"]["expected"]),
            actual_output,
            html_status(result_dict["acl_services"]["status"])
    ])
    logging.info(f"{fw_name}: Access ACL Result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict