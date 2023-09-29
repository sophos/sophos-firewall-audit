from sophosfirewall_python.firewallapi import SophosFirewall
import logging
import sys

def eval_admin_services(fw_obj: SophosFirewall,
                     fw_name: str,
                      settings: dict):
    """Verify Admin Services on WAN (Configure > Network > Zones > WAN) 

    Args:
        fw_obj (SophosFirewall): SophosFirewall object
        fw_name (str): Firewall hostname
        settings (dict): Audit settings

    Returns:
        dict: Audit results and output table(s)
    """

    expected_services = sorted(settings["services"])
    if not expected_services:
        expected_services = ["No services enabled"]

    for i in range(1,3):
        try:
            result = fw_obj.get_zone(name="WAN", verify=False)
        except Exception as err:
            logging.exception(f"Error while retrieving WAN zone from firewall {fw_name}: {err}")
            if i < 3:
                logging.info(f"Retry #{i}")
                continue
            else:
                logging.exception("Unrecoverable error, exiting!")
                sys.exit(1)
        break

    if "ApplianceAccess" in result["Response"]["Zone"]:
        services = [service for service in result["Response"]["Zone"]["ApplianceAccess"]["AdminServices"].keys()]
    else:
        services = ["No services enabled"]

    result_dict = {
        "services": {
            "expected": expected_services,
            "actual": services
        }
    }
    if services == expected_services:
        result_dict["services"]["status"] = "AUDIT_PASS"
    else:
        result_dict["services"]["status"] = "AUDIT_FAIL"
    
    if result_dict["services"]["status"] == "AUDIT_FAIL":
        result_dict["audit_result"] = "FAIL"
    else:
        result_dict["audit_result"] = "PASS"
    
    output = []

    output.append([
            "WAN Zone Admin Services",
            "Configure > Network > Zones > WAN",
            "admin services",
             "\n".join(result_dict["services"]["expected"]),
             "\n".join(result_dict["services"]["actual"]),
             result_dict["services"]["status"]
        ])

    logging.info(f"{fw_name}: WAN Zone Admin Services Result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict