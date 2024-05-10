"""Sophos Firewall Audit - loginsecurity.py
 Copyright 2024 Sophos Ltd.  All rights reserved.
 Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
 permissions and limitations under the License.
"""
from sophosfirewall_python.firewallapi import SophosFirewall
from sophos_firewall_audit.utils import html_status, html_yellow
import logging
import sys


def eval_loginsecurity(fw_obj: SophosFirewall, fw_name: str, settings: dict):
    """Verify Login Security (System > Administration > Admin and user settings)

    Args:
        fw_obj (SophosFirewall): SophosFirewall object
        fw_name (str): Firewall hostname
        settings (dict): Audit settings

    Returns:
        dict: Audit results and output table(s)
    """
    output = []

    for i in range(1, 3):
        try:
            result = fw_obj.get_admin_settings()
        except Exception as err:
            logging.exception(
                f"Error while retrieving Admin settings for firewall {fw_name}: {err}"
            )
            if i < 3:
                logging.info(f"Retry #{i}")
                continue
            else:
                logging.exception("Unrecoverable error, exiting!")
                sys.exit(1)
        break

    result["Response"]["AdminSettings"].pop("WebAdminSettings")
    result["Response"]["AdminSettings"].pop("@transactionid")
    result["Response"]["AdminSettings"].pop("HostnameSettings")
    actual_settings = {}
    for settings_group in result["Response"]["AdminSettings"]:
        actual_settings[settings_group] = result["Response"]["AdminSettings"][
            settings_group
        ]

    expected_settings = settings["login_security"]

    results = []
    for key in expected_settings:
        if isinstance(expected_settings[key], dict):
            for category in expected_settings[key]:
                settings_dict = {}
                settings_dict[key] = {}
                settings_dict[key][category] = {}
                if isinstance(expected_settings[key][category], dict):
                    for subcategory in expected_settings[key][category]:
                        settings_dict[key][category][subcategory] = {}
                        settings_dict[key][category][subcategory][
                            "expected"
                        ] = expected_settings[key][category][subcategory]
                        settings_dict[key][category][subcategory][
                            "actual"
                        ] = actual_settings[key][category][subcategory]
                else:
                    settings_dict[key][category]["expected"] = expected_settings[key][
                        category
                    ]
                    settings_dict[key][category]["actual"] = actual_settings[key][
                        category
                    ]

                results.append(settings_dict)
        else:
            settings_dict = {}
            settings_dict[key] = {}
            settings_dict[key]["expected"] = expected_settings[key]
            settings_dict[key]["actual"] = actual_settings[key]
            results.append(settings_dict)

    result_dict = {
        "audit_result": "PASS",
        "pass_ct": 0,
        "fail_ct": 0,
        "loginsecurity": {"expected": expected_settings, "actual": actual_settings},
    }
    for result in results:
        status = "AUDIT_PASS"
        for lvl1 in result:
            if "expected" in result[lvl1]:
                if result[lvl1]["expected"] != result[lvl1]["actual"]:
                    status = "AUDIT_FAIL"
                    result_dict["audit_result"] = "FAIL"
                    result_dict["fail_ct"] += 1
                else:
                    result_dict["pass_ct"] += 1
                output.append(
                    [
                        "Admin and user settings",
                        "System > Administration > Admin and user settings",
                        "Login disclaimer settings",
                        f"{lvl1}: {result[lvl1]['expected']}",
                        f"{lvl1}: {html_yellow(result[lvl1]['actual']) if status == 'AUDIT_FAIL' else result[lvl1]['actual']}",
                        html_status(status),
                    ]
                )
                continue
            for lvl2 in result[lvl1]:
                if "expected" in result[lvl1][lvl2]:
                    if result[lvl1][lvl2]["expected"] != result[lvl1][lvl2]["actual"]:
                        status = "AUDIT_FAIL"
                        result_dict["audit_result"] = "FAIL"
                        result_dict["fail_ct"] += 1
                    else:
                        result_dict["pass_ct"] += 1
                    output.append(
                        [
                            "Admin and user settings",
                            "System > Administration > Admin and user settings",
                            lvl1,
                            f"{lvl2}: {result[lvl1][lvl2]['expected']}",
                            f"{lvl2}: {html_yellow(result[lvl1][lvl2]['actual']) if status == 'AUDIT_FAIL' else result[lvl1][lvl2]['actual']}",
                            html_status(status),
                        ]
                    )
                    continue
                for lvl3 in result[lvl1][lvl2]:
                    if "expected" in result[lvl1][lvl2][lvl3]:
                        if (
                            result[lvl1][lvl2][lvl3]["expected"]
                            != result[lvl1][lvl2][lvl3]["actual"]
                        ):
                            status = "AUDIT_FAIL"
                            result_dict["audit_result"] = "FAIL"
                            result_dict["fail_ct"] += 1
                        else:
                            result_dict["pass_ct"] += 1
                        output.append(
                            [
                                "Admin and user settings",
                                "System > Administration > Admin and user settings",
                                f"{lvl1}\n{lvl2}",
                                f"{lvl3}: {result[lvl1][lvl2][lvl3]['expected']}",
                                f"{lvl3}: {html_yellow(result[lvl1][lvl2][lvl3]['actual']) if status == 'AUDIT_FAIL' else result[lvl1][lvl2][lvl3]['actual']}",
                                html_status(status),
                            ]
                        )

    logging.info(f"{fw_name}: Login Security Result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict
