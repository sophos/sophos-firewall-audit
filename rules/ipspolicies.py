from sophosfirewall_python.firewallapi import SophosFirewall
import logging
import sys

def eval_ips_policies(fw_obj: SophosFirewall,
                     fw_name: str,
                      settings: dict):
    """Verify IPS Policies (Protect > Intrusion prevention > IPS policies) 

    Args:
        fw_obj (SophosFirewall): SophosFirewall object
        fw_name (str): Firewall hostname
        settings (dict): Audit settings

    Returns:
        dict: Audit results and output table(s)
    """

    expected_policies = sorted(settings["policies"])

    for i in range(1,3):
        try:
            result = fw_obj.get_ips_policy(verify=False)
        except Exception as err:
            logging.exception(f"Error while retrieving IPS policies for firewall {fw_name}: {err}")
            if i < 3:
                logging.info(f"Retry #{i}")
                continue
            else:
                logging.exception("Unrecoverable error, exiting!")
                sys.exit(1)
        break
    
    actual_policies = sorted([policy["Name"] for policy in result["Response"]["IPSPolicy"]])

    result_dict = {
        "policies": {
            "expected": expected_policies,
            "actual": actual_policies
        },
        "audit_result": "PASS"
    }
    for policy in expected_policies:
        result_dict["policies"][policy] = {}
        if policy in result_dict["policies"]["actual"]: 
            result_dict["policies"][policy]["status"] = "AUDIT_PASS"
        else:
            result_dict["policies"][policy]["status"] = "AUDIT_FAIL"
            result_dict["audit_result"] = "FAIL"
    
    output = []

    for policy in expected_policies:
        output.append([
                "IPS Policies",
                "(Protect > Intrusion prevention > IPS policies",
                "ips policies",
                policy,
                "\n".join(result_dict["policies"]["actual"]),
                result_dict["policies"][policy]["status"]
            ])

    logging.info(f"{fw_name}: IPS Policies Result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict