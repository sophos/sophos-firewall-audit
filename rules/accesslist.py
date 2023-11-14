from sophosfirewall_python.firewallapi import SophosFirewall
from utils import html_status
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

    for i in range(1,4):
        try:
            acl_result = fw_obj.get_acl_rule()
        except Exception as err:
            logging.exception(f"Error while retrieving access list for firewall {fw_name}: {err}")
            if i < 3:
                logging.info(f"Retry #{i}")
                continue
            elif i == 3:
                logging.exception("Unrecoverable error, exiting!")
                sys.exit(1)
        break

    if isinstance(acl_result["Response"]["LocalServiceACL"], dict):
        hostgroups = sorted(list(set(acl_result["Response"]["LocalServiceACL"]["Hosts"]["Host"])))
        services = sorted(list(set(acl_result["Response"]["LocalServiceACL"]["Services"]["Service"])))

    if isinstance(acl_result["Response"]["LocalServiceACL"], list):
        hostgroups = []
        services = []
        for acl in acl_result["Response"]["LocalServiceACL"]:
            if "Hosts" in acl:
                if isinstance(acl["Hosts"]["Host"], list):
                    for host in acl["Hosts"]["Host"]:
                        hostgroups.append(host)
                else:
                    hostgroups.append(acl["Hosts"]["Host"])
            if isinstance(acl["Services"]["Service"], list):
                for service in acl["Services"]["Service"]:
                    services.append(service)
            else:
                services.append(acl["Services"]["Service"])
            hostgroups = sorted(list(set(hostgroups)))
            services = sorted(list(set(services)))

    result_dict = {
        "acl_hostgroups": {
            "expected": expected_hostgroups,
            "actual": hostgroups
        },
        "acl_services": {
            "expected": expected_services,
            "actual": services
        },
        "pass_ct": 0,
        "fail_ct": 0
    }
    if hostgroups == expected_hostgroups:
        result_dict["acl_hostgroups"]["status"] = "AUDIT_PASS"
        result_dict["pass_ct"] += 1
    else:
        result_dict["acl_hostgroups"]["status"] = "AUDIT_FAIL"
        result_dict["fail_ct"] += 1

    if services == expected_services:
        result_dict["acl_services"]["status"] = "AUDIT_PASS"
        result_dict["pass_ct"] += 1
    else:
        result_dict["acl_services"]["status"] = "AUDIT_FAIL"
        result_dict["fail_ct"] += 1
    
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
             html_status(result_dict["acl_hostgroups"]["status"])
        ])

    output.append([
        "Access ACL",
        "System > Administration > Device Access > \nLocal service ACL exception",
        "services",
            "\n".join(result_dict["acl_services"]["expected"]),
            "\n".join(result_dict["acl_services"]["actual"]),
            html_status(result_dict["acl_services"]["status"])
    ])
    logging.info(f"{fw_name}: Access ACL Result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict