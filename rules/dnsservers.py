from sophosfirewall_python.firewallapi import SophosFirewall
import logging
import sys

def eval_dns_servers(fw_obj: SophosFirewall,
                     fw_name: str,
                      settings: dict):
    """Verify DNS Servers (Configure > Network > DNS) 

    Args:
        fw_obj (SophosFirewall): SophosFirewall object
        fw_name (str): Firewall hostname
        settings (dict): Audit settings

    Returns:
        dict: Audit results and output table(s)
    """

    expected_servers = sorted(settings["dns_servers"])

    for i in range(1,3):
        try:
            result = fw_obj.get_dns_forwarders()
        except Exception as err:
            logging.exception(f"Error while retrieving authentication servers for firewall {fw_name}: {err}")
            if i < 3:
                logging.info(f"Retry #{i}")
                continue
            else:
                logging.exception("Unrecoverable error, exiting!")
                sys.exit(1)
        break

    server_list = result["Response"]["DNS"]["IPv4Settings"]["DNSIPList"]
    servers = sorted([server_list[key] for key in server_list.keys()])

    result_dict = {
        "servers": {
            "expected": expected_servers,
            "actual": servers
        }
    }
    if servers == expected_servers:
        result_dict["servers"]["status"] = "AUDIT_PASS"
    else:
        result_dict["servers"]["status"] = "AUDIT_FAIL"
    
    if result_dict["servers"]["status"] == "AUDIT_FAIL":
        result_dict["audit_result"] = "FAIL"
    else:
        result_dict["audit_result"] = "PASS"
    
    output = []

    output.append([
            "DNS Servers",
            "Configure > Network > DNS",
            "Static DNS",
             "\n".join(result_dict["servers"]["expected"]),
             "\n".join(result_dict["servers"]["actual"]),
             result_dict["servers"]["status"]
        ])

    logging.info(f"{fw_name}: DNS Servers Result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict