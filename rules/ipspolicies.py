from sophosfirewall_python.firewallapi import SophosFirewall
from utils import html_status, format_diff
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

    result_dict = {
        "policies": {
            "expected": expected_policies,
            "actual": actual_policies
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
    
    output = []

    if result_dict["policies"]["status"] == "AUDIT_FAIL":
        diff = unified_diff(result_dict["policies"]["expected"], 
                                   result_dict["policies"]["actual"], n=100000000)
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