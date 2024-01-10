from sophosfirewall_python.firewallapi import SophosFirewall
from utils import html_status
import logging
import sys

def eval_admin_authen(fw_obj: SophosFirewall,
                     fw_name: str,
                      settings: dict):
    """Verify Admin Authentication (Configure > Authentication > Servers) 

    Args:
        fw_obj (SophosFirewall): SophosFirewall object
        fw_name (str): Firewall hostname
        settings (dict): Audit settings

    Returns:
        dict: Audit results and output table(s)
    """

    expected_servers = sorted(settings["servers"])

    for i in range(1,3):
        try:
            result = fw_obj.get_admin_authen()
        except Exception as err:
            logging.exception(f"Error while retrieving authentication servers for firewall {fw_name}: {err}")
            if i < 3:
                logging.info(f"Retry #{i}")
                continue
            else:
                logging.exception("Unrecoverable error, exiting!")
                sys.exit(1)
        break

    servers = sorted([server for server in result["Response"]["AdminAuthentication"]['AuthenticationServerList']['AuthenticationServer']
                      if not server == "Local"])

    result_dict = {
        "servers": {
            "expected": expected_servers,
            "actual": servers
        },
        "pass_ct": 0,
        "fail_ct": 0
    }
    if servers == expected_servers:
        result_dict["servers"]["status"] = "AUDIT_PASS"
        result_dict["pass_ct"] += 1
    else:
        result_dict["servers"]["status"] = "AUDIT_FAIL"
        result_dict["fail_ct"] += 1
    
    if result_dict["servers"]["status"] == "AUDIT_FAIL":
        result_dict["audit_result"] = "FAIL"
    else:
        result_dict["audit_result"] = "PASS"
    
    output = []

    output.append([
            "Authentication Servers",
            "Configure > Authentication > Servers",
            "servers",
             "\n".join(result_dict["servers"]["expected"]),
             "\n".join(result_dict["servers"]["actual"]),
             html_status(result_dict["servers"]["status"])
        ])

    logging.info(f"{fw_name}: Authentication Servers Result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict