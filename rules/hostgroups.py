from sophosfirewall_python.firewallapi import SophosFirewall
import logging
import sys

def eval_hostgroups(fw_obj: SophosFirewall,
                     fw_name: str,
                      settings: dict):
    """Verify specified IP Host Groups (System > Hosts and services > IP host group) 

    Args:
        fw_obj (SophosFirewall): SophosFirewall object
        fw_name (str): Firewall hostname
        settings (dict): Audit settings

    Returns:
        dict: Audit results and output table(s)
    """
    result_dict = {
        "audit_result": "PASS"
    }
    output = []
    for host_group in settings["groups"]:
        expected_hosts = sorted(host_group["hosts"])

        for i in range(1,3):
            try:
                result = fw_obj.get_ip_hostgroup(name=host_group["name"], verify=False)
            except Exception as err:
                logging.exception(f"Error while retrieving IP host group {host_group['name']} for firewall {fw_name}: {err}")
                if i < 3:
                    logging.info(f"Retry #{i}")
                    continue
                else:
                    logging.exception("Unrecoverable error, exiting!")
                    sys.exit(1)
            break

        actual_hosts = sorted([host for host in result["Response"]["IPHostGroup"]["HostList"]["Host"]])

        result_dict["hostgroups"] =  {
                "expected": expected_hosts,
                "actual": actual_hosts,
                "hostgroup_name": host_group["name"]
            }
        
        if actual_hosts == expected_hosts:
            result_dict["hostgroups"]["status"] = "AUDIT_PASS"
        else:
            result_dict["hostgroups"]["status"] = "AUDIT_FAIL"
        
        if result_dict["hostgroups"]["status"] == "AUDIT_FAIL":
            result_dict["audit_result"] = "FAIL"

        output.append([
                "IP Host Group",
                "System > Hosts and services > IP host group",
                f"IP Host Group: {host_group['name']}",
                "\n".join(result_dict["hostgroups"]["expected"]),
                "\n".join(result_dict["hostgroups"]["actual"]),
                result_dict["hostgroups"]["status"]
            ])
        

    logging.info(f"{fw_name}: Host Groups Result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict