from sophosfirewall_python.firewallapi import SophosFirewall
from utils import html_status
from utils import html_yellow
import logging
import sys

def eval_atp(fw_obj: SophosFirewall,
                     fw_name: str,
                      settings: dict):
    """Verify Active Threat Response (Protect > Active threat response > Sophos X-Ops threat feeds) 

    Args:
        fw_obj (SophosFirewall): SophosFirewall object
        fw_name (str): Firewall hostname
        settings (dict): Audit settings

    Returns:
        dict: Audit results and output table(s)
    """

    expected = settings
    expected_state = settings["state"]
    expected_policy = settings["policy"]

    for i in range(1,3):
        try:
            result = fw_obj.get_tag("ATP")
        except Exception as err:
            logging.exception(f"Error while retrieving active threat response configuration for firewall {fw_name}: {err}")
            if i < 3:
                logging.info(f"Retry #{i}")
                continue
            else:
                logging.exception("Unrecoverable error, exiting!")
                sys.exit(1)
        break
    
    actual = result["Response"]["ATP"]
    actual_state = result["Response"]["ATP"]["ThreatProtectionStatus"]
    actual_policy = result["Response"]["ATP"]["Policy"]

    result_dict = {
        "atp": {
            "expected": expected,
            "actual": actual,
            "state": {
                "expected": expected_state,
                "actual": actual_state
            },
            "policy": {
                "expected": expected_policy,
                "actual": actual_policy
            }
        },
        "pass_ct": 0,
        "fail_ct": 0
    }
    if actual_state == expected_state:
        result_dict["atp"]["state"]["status"] = "AUDIT_PASS"
        result_dict["pass_ct"] += 1
    else:
        result_dict["atp"]["state"]["status"] = "AUDIT_FAIL"
        result_dict["fail_ct"] += 1
    
    if actual_policy == expected_policy:
        result_dict["atp"]["policy"]["status"] = "AUDIT_PASS"
        result_dict["pass_ct"] += 1
    else:
        result_dict["atp"]["policy"]["status"] = "AUDIT_FAIL"
        result_dict["fail_ct"] += 1

    if result_dict["atp"]["state"]["status"] == "AUDIT_FAIL" or result_dict["atp"]["policy"]["status"] == "AUDIT_FAIL":
        result_dict["audit_result"] = "FAIL"
    else:
        result_dict["audit_result"] = "PASS"
    
    output = []

    output.append([
            "Active Threat Response Settings",
            "Protect > Active threat response > Sophos X-Ops threat feeds",
            "enabled/disabled",
             result_dict["atp"]["state"]["expected"],
             html_yellow(result_dict["atp"]["state"]["actual"]) if result_dict["atp"]["state"]["status"] == "AUDIT_FAIL"
               else result_dict["atp"]["state"]["actual"],
             html_status(result_dict["atp"]["state"]["status"])
        ])
    
    output.append([
            "Active Threat Response Settings",
            "Protect > Active threat response > Sophos X-Ops threat feeds",
            "action",
             result_dict["atp"]["policy"]["expected"],
             html_yellow(result_dict["atp"]["policy"]["actual"]) if result_dict["atp"]["policy"]["status"] == "AUDIT_FAIL"
              else result_dict["atp"]["policy"]["actual"],
             html_status(result_dict["atp"]["policy"]["status"])
        ])

    logging.info(f"{fw_name}: Active Threat Response Result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict