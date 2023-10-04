from sophosfirewall_python.firewallapi import SophosFirewall, SophosFirewallZeroRecords
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
        if not expected[key] == actual[key]:
            status = "AUDIT_FAIL"
            result_dict["audit_result"] = "FAIL"
            result_dict["fail_ct"] += 1
        else:
            result_dict["pass_ct"] += 1
        output.append([
                "SNMPv3",
                "System > Administration > SNMP",
                key,
                expected[key],
                actual[key],
                status
            ])

    logging.info(f"{fw_name}: SNMPv3 Result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict