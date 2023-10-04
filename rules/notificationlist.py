from sophosfirewall_python.firewallapi import SophosFirewall
import logging
import sys

def eval_notification_list(fw_obj: SophosFirewall,
                     fw_name: str,
                      settings: dict):
    """Verify Notification List settings (Configure > System services > Notification list) 

    Args:
        fw_obj (SophosFirewall): SophosFirewall object
        fw_name (str): Firewall hostname
        settings (dict): Audit settings

    Returns:
        dict: Audit results and output table(s)
    """

    expected_settings = settings["notification_list"]

    for i in range(1,3):
        try:
            result = fw_obj.get_tag("Notificationlist")
        except Exception as err:
            logging.exception(f"Error while retrieving Notification List settings for firewall {fw_name}: {err}")
            if i < 3:
                logging.info(f"Retry #{i}")
                continue
            else:
                logging.exception("Unrecoverable error, exiting!")
                sys.exit(1)
        break

    actual_settings = result["Response"]["Notificationlist"]

    result_dict = {
        "notification_list": {
            "expected": expected_settings,
            "actual": actual_settings,
            "status": "AUDIT_PASS"
        },
        "audit_result": "PASS",
        "pass_ct": 0,
        "fail_ct": 0
    }

    expected_list = []
    actual_list = []
    for setting in expected_settings.keys():
        expected_list.append(f"{setting}: {expected_settings[setting]}")
        actual_list.append(f"{setting}: {actual_settings[setting]}")
        if not expected_settings[setting] == actual_settings[setting]:
            result_dict["notification_list"]["status"] = "AUDIT_FAIL"
            result_dict["audit_result"] = "FAIL"
            result_dict["fail_ct"] += 1
            # print(f"expected_settings: {setting}: {expected_settings[setting]}")
            # print(f"actual_settings: {setting}: {actual_settings[setting]}")
    if result_dict["audit_result"] == "PASS":
        result_dict["pass_ct"] += 1
     
    output = []

    output.append([
            "Notification List Settings",
            "Configure > System services > Notification List settings",
            "notification list",
             "\n".join(expected_list),
             "\n".join(actual_list),
             result_dict["notification_list"]["status"]
        ])

    logging.info(f"{fw_name}: Notification Settings Result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict