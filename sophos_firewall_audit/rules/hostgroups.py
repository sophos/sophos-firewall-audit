"""Sophos Firewall Audit - hostgroups.py
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

def eval_hostgroups(fw_obj: SophosFirewall,
                     fw_name: str,
                      settings: dict):
    """Verify specified IP Host Groups (System > Hosts and services > IP host group) 

    Args:
        fw_obj (SophosFirewall): SophosFirewall object
        fw_name (str): Firewall hostname
        settings (dict): Audit settings

    Returns:
        dict: Audit results and output table(s)
    """
    result_dict = {
        "audit_result": "PASS",
        "pass_ct": 0,
        "fail_ct": 0
    }

    output = []
    for host_group in settings["groups"]:
        expected_hosts = sorted(host_group["hosts"])

        for i in range(1,3):
            try:
                result = fw_obj.get_ip_hostgroup(name=host_group["name"])
            except RequestException as err:
                logging.exception(f"Error while retrieving IP host group {host_group['name']} for firewall {fw_name}: {err}")
                if i < 3:
                    logging.info(f"Retry #{i}")
                    continue
                else:
                    logging.exception("Unrecoverable error, exiting!")
                    sys.exit(1)
            except SophosFirewallZeroRecords as err:
                result = None
                break
            
        if result:
            if "HostList" in result["Response"]["IPHostGroup"]:
                actual_hosts = sorted([host for host in result["Response"]["IPHostGroup"]["HostList"]["Host"]])
            else:
                actual_hosts = ["Not Found"]

            result_dict["hostgroups"] =  {
                    "expected": expected_hosts,
                    "actual": actual_hosts,
                    "hostgroup_name": host_group["name"]
                }
            
            if actual_hosts == expected_hosts:
                result_dict["hostgroups"]["status"] = "AUDIT_PASS"
                result_dict["pass_ct"] += 1
            else:
                result_dict["hostgroups"]["status"] = "AUDIT_FAIL"
                result_dict["fail_ct"] += 1
            
            if result_dict["hostgroups"]["status"] == "AUDIT_FAIL":
                result_dict["audit_result"] = "FAIL"

            if result_dict["hostgroups"]["status"] == "AUDIT_FAIL":
                diff = unified_diff(sorted(result_dict["hostgroups"]["expected"]), sorted(result_dict["hostgroups"]["actual"]), n=100000000)
                actual_output = "\n".join(format_diff(diff))
            else:
                actual_output = "\n".join(result_dict["hostgroups"]["actual"])
        else:
            result_dict["hostgroups"] =  {
                    "expected": expected_hosts,
                    "actual": f"Host group {host_group['name']} not found!",
                    "hostgroup_name": host_group["name"]
                }
            result_dict["hostgroups"]["status"] = "AUDIT_FAIL"
            result_dict["fail_ct"] += 1
            result_dict["audit_result"] = "FAIL"
            actual_output = f"Hostgroup {host_group['name']} not found!"

        output.append([
                "IP Host Group",
                "System > Hosts and services > IP host group",
                f"IP Host Group: {host_group['name']}",
                "\n".join(result_dict["hostgroups"]["expected"]),
                actual_output,
                html_status(result_dict["hostgroups"]["status"])
            ])

    logging.info(f"{fw_name}: Host Groups Result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict