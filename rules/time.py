from sophosfirewall_python.firewallapi import SophosFirewall
from utils import html_status
from utils import html_yellow
import logging
import sys

def eval_time(fw_obj: SophosFirewall,
                     fw_name: str,
                      settings: dict):
    """Verify System Time Settings (System > Administration > Time) 

    Args:
        fw_obj (SophosFirewall): SophosFirewall object
        fw_name (str): Firewall hostname
        settings (dict): Audit settings

    Returns:
        dict: Audit results and output table(s)
    """

    expected = settings["timezone"]

    for i in range(1,3):
        try:
            result = fw_obj.get_tag("Time")
        except Exception as err:
            logging.exception(f"Error while retrieving time configuration for firewall {fw_name}: {err}")
            if i < 3:
                logging.info(f"Retry #{i}")
                continue
            else:
                logging.exception("Unrecoverable error, exiting!")
                sys.exit(1)
        break
    
    actual = result["Response"]["Time"]["TimeZone"]

    result_dict = {
        "time": {
            "expected": expected,
            "actual": actual
        },
        "pass_ct": 0,
        "fail_ct": 0
    }
    if actual == expected:
        result_dict["time"]["status"] = "AUDIT_PASS"
        result_dict["pass_ct"] += 1
    else:
        result_dict["time"]["status"] = "AUDIT_FAIL"
        result_dict["fail_ct"] += 1
    
    if result_dict["time"]["status"] == "AUDIT_FAIL":
        result_dict["audit_result"] = "FAIL"
    else:
        result_dict["audit_result"] = "PASS"
    
    output = []

    output.append([
            "Timezone",
            "System > Administration > Time",
            "timezone",
             result_dict["time"]["expected"],
             html_yellow(result_dict["time"]["actual"]) if result_dict["time"]["status"] == "AUDIT_FAIL"
               else result_dict["time"]["actual"],
             html_status(result_dict["time"]["status"])
        ])
    

    logging.info(f"{fw_name}: Timezone Result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict