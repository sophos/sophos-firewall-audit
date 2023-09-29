from sophosfirewall_python.firewallapi import SophosFirewall
import logging
import sys

def eval_access_list(fw_obj: SophosFirewall,
                     fw_name: str,
                      settings: dict):
    """Verify Local service ACL exception rule (System > Administration > Device Access > Local service ACL exception) 

    Args:
        fw_obj (SophosFirewall): SophosFirewall object
        fw_name (str): Firewall hostname
        settings (dict): Audit settings

    Returns:
        dict: Audit results and output table(s)
    """

    expected_hostgroups = sorted(settings["hostgroups"])
    expected_services = sorted(settings["services"])

    for i in range(1,3):
        try:
            acl_result = fw_obj.get_acl_rule(verify=False)
        except Exception as err:
            logging.exception(f"Error while retrieving access list for firewall {fw_name}: {err}")
            if i < 3:
                logging.info(f"Retry #{i}")
                continue
            else:
                logging.exception("Unrecoverable error, exiting!")
                sys.exit(1)
        break

    hostgroups = sorted(acl_result["Response"]["LocalServiceACL"]["Hosts"]["Host"])
    services = sorted(acl_result["Response"]["LocalServiceACL"]["Services"]["Service"])

    result_dict = {
        "acl_hostgroups": {
            "expected": expected_hostgroups,
            "actual": hostgroups
        },
        "acl_services": {
            "expected": expected_services,
            "actual": services
        }
    }
    if hostgroups == expected_hostgroups:
        result_dict["acl_hostgroups"]["status"] = "AUDIT_PASS"
    else:
        result_dict["acl_hostgroups"]["status"] = "AUDIT_FAIL"

    if services == expected_services:
        result_dict["acl_services"]["status"] = "AUDIT_PASS"
    else:
        result_dict["acl_services"]["status"] = "AUDIT_FAIL"
    
    if result_dict["acl_hostgroups"]["status"] == "AUDIT_FAIL" or result_dict["acl_services"]["status"] == "AUDIT_FAIL":
        result_dict["audit_result"] = "FAIL"
    else:
        result_dict["audit_result"] = "PASS"
   
    output = []

    output.append([
            "Access ACL",
            "System > Administration > Device Access > \nLocal service ACL exception",
            "host groups",
             "\n".join(result_dict["acl_hostgroups"]["expected"]),
             "\n".join(result_dict["acl_hostgroups"]["actual"]),
             result_dict["acl_hostgroups"]["status"]
        ])

    output.append([
        "Access ACL",
        "System > Administration > Device Access > \nLocal service ACL exception",
        "services",
            "\n".join(result_dict["acl_services"]["expected"]),
            "\n".join(result_dict["acl_services"]["actual"]),
            result_dict["acl_services"]["status"]
    ])
    logging.info(f"{fw_name}: Access ACL Result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict