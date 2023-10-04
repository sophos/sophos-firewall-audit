from sophosfirewall_python.firewallapi import SophosFirewall
import logging
import sys

def eval_backup(fw_obj: SophosFirewall,
                     fw_name: str,
                      settings: dict):
    """Verify Scheduled Backup settings (System > Backup & firmware > Backup) 

    Args:
        fw_obj (SophosFirewall): SophosFirewall object
        fw_name (str): Firewall hostname
        settings (dict): Audit settings

    Returns:
        dict: Audit results and output table(s)
    """

    expected_settings = settings["scheduled_backup"]

    for i in range(1,3):
        try:
            result = fw_obj.get_backup()
        except Exception as err:
            logging.exception(f"Error while retrieving Backup settings for firewall {fw_name}: {err}")
            if i < 3:
                logging.info(f"Retry #{i}")
                continue
            else:
                logging.exception("Unrecoverable error, exiting!")
                sys.exit(1)
        break

    actual_settings = result["Response"]["BackupRestore"]["ScheduleBackup"]

    result_dict = {
        "backup": {
            "expected": expected_settings,
            "actual": actual_settings,
            "status": "AUDIT_PASS"
        }
    }
    result_dict["audit_result"] = "PASS"

    expected_list = []
    actual_list = []
    for setting in expected_settings.keys():
        if actual_settings[setting] == 'None':
            actual_settings[setting] = None
        expected_list.append(f"{setting}: {expected_settings[setting]}")
        actual_list.append(f"{setting}: {actual_settings[setting]}")
        if not expected_settings[setting] == actual_settings[setting]:
            result_dict["backup"]["status"] = "AUDIT_FAIL"
            result_dict["audit_result"] = "FAIL"
            # print(f"expected_settings: {setting}: {expected_settings[setting]}")
            # print(f"actual_settings: {setting}: {actual_settings[setting]}")
     
    output = []

    output.append([
            "Scheduled Backup",
            "System > Backup & firmware > Backup & restore",
            "backup",
             "\n".join(expected_list),
             "\n".join(actual_list),
             result_dict["backup"]["status"]
        ])

    logging.info(f"{fw_name}: Scheduled Backup Result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict