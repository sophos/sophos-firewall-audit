from sophosfirewall_python.firewallapi import SophosFirewall
from utils import html_status, html_red
from difflib import unified_diff
import logging
import sys
import re

def format_diff(diff):
    """Remove lines with ---, +++, @@ and style diff lines in red.

    Args:
        diff (list): A list containing the diff

    Returns:
        list: formatted output
    """
    output = []
    for line in diff:
        patterns = ["-{3}", "\+{3}", "\@{2}"]
        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                break
        if not match:
            if line.startswitch("-") or line.startswitch("+"):
                output.append(html_red(line))
            else:
                output.append(line)
    return output

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
            except Exception as err:
                logging.exception(f"Error while retrieving IP host group {host_group['name']} for firewall {fw_name}: {err}")
                if i < 3:
                    logging.info(f"Retry #{i}")
                    continue
                else:
                    logging.exception("Unrecoverable error, exiting!")
                    sys.exit(1)
            break

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
            diff = "\n".join(unified_diff(result_dict["hostgroups"]["expected"], result_dict["hostgroups"]["actual"], n=100000000))
            actual_output = format_diff(diff)
        else:
            actual_output = "\n".join(result_dict["hostgroups"]["actual"])

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