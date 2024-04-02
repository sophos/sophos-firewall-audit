from sophosfirewall_python.firewallapi import SophosFirewall, SophosFirewallZeroRecords
from utils import html_status, format_diff
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

        if key == "AuthorizedHosts" and not actual[key] == "None" and status == "AUDIT_FAIL":
            actual_output = '\n'.join(format_diff(unified_diff(sorted(expected[key]), sorted(actual[key]), n=1000000000)))
        elif key == "AuthorizedHosts" and not actual[key] == "None" and status == "AUDIT_PASS":
            actual_output = '\n'.join(actual[key])
        else:
            actual_output = actual[key]

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