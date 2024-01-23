from sophosfirewall_python.firewallapi import SophosFirewall
from utils import html_yellow, html_status
import logging
import sys

def eval_central_mgmt(fw_obj: SophosFirewall,
                     fw_name: str,
                      settings: dict):
    """Verify Central Management (System > Sophos Central) 

    Args:
        fw_obj (SophosFirewall): SophosFirewall object
        fw_name (str): Firewall hostname
        settings (dict): Audit settings

    Returns:
        dict: Audit results and output table(s)
    """

    expected_settings = settings["central_management"]

    for i in range(1,3):
        try:
            result = fw_obj.get_tag("EnableCloudCentralManagement")
        except Exception as err:
            logging.exception(f"Error while retrieving Central Management settings for firewall {fw_name}: {err}")
            if i < 3:
                logging.info(f"Retry #{i}")
                continue
            else:
                logging.exception("Unrecoverable error, exiting!")
                sys.exit(1)
        break

    actual_settings = result["Response"]["EnableCloudCentralManagement"]

    result_dict = {
        "central_management": {
            "expected": expected_settings,
            "actual": actual_settings,
            "status": "AUDIT_PASS"
        },
        "audit_result": "PASS",
        "pass_ct": 0,
        "fail_ct": 0
    }

    expected_list = []
    actual_list = []
    for setting in expected_settings.keys():
        expected_list.append(f"{setting}: {expected_settings[setting]}")
        if not expected_settings[setting] == actual_settings[setting]:
            actual_list.append(f"{setting}: {html_yellow(actual_settings[setting])}")
            result_dict["central_management"]["status"] = "AUDIT_FAIL"
            result_dict["audit_result"] = "FAIL"
        else:
            actual_list.append(f"{setting}: {actual_settings[setting]}")
    if result_dict["audit_result"] == "PASS":
        result_dict["pass_ct"] += 1
    else:
        result_dict["fail_ct"] += 1
     
    output = []

    output.append([
            "Sophos Central Management",
            "System > Sophos Central",
            "central management",
             "\n".join(expected_list),
             "\n".join(actual_list),
             html_status(result_dict["central_management"]["status"])
        ])

    logging.info(f"{fw_name}: Central Management Result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict