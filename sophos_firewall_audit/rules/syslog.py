"""Sophos Firewall Audit - syslog.py
 Copyright 2024 Sophos Ltd.  All rights reserved.
 Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
 permissions and limitations under the License.
"""

from sophosfirewall_python.firewallapi import SophosFirewall
from sophos_firewall_audit.utils import html_yellow, html_status
import logging
import sys

def eval_syslog(fw_obj: SophosFirewall,
                     fw_name: str,
                      settings: dict):
    """Verify Syslog settings (Configure > System services > Log settings) 

    Args:
        fw_obj (SophosFirewall): SophosFirewall object
        fw_name (str): Firewall hostname
        settings (dict): Audit settings

    Returns:
        dict: Audit results and output table(s)
    """
    output = []

    for i in range(1,3):
        try:
            result = fw_obj.get_syslog_server()
        except Exception as err:
            logging.exception(f"Error while retrieving Syslog settings for firewall {fw_name}: {err}")
            if i < 3:
                logging.info(f"Retry #{i}")
                continue
            else:
                logging.exception("Unrecoverable error, exiting!")
                sys.exit(1)
        break

    actual_settings = {}
    api_version = result["Response"]["@APIVersion"]
    for settings_group in result["Response"]["SyslogServers"]:
        actual_settings[settings_group["Name"]] = settings_group

    # audit_settings.yaml.example ships syslog as a list of server
    # definitions. Region-keyed dicts (like dns_servers) are also
    # supported: { na: [...], emea: [...] }.
    if isinstance(settings, list):
        expected_settings = settings
    elif isinstance(settings, dict):
        expected_settings = settings.get(fw_obj.region, settings.get("default"))
        if expected_settings is None:
            logging.error(
                "Syslog settings must be a list of servers, or a dict keyed "
                "by firewall region (got keys: %s)",
                list(settings.keys()),
            )
            sys.exit(1)
        if isinstance(expected_settings, dict):
            # Misconfigured: entire syslog block was treated as one region map
            # without a matching region key — reject clearly.
            logging.error(
                "Syslog settings for region %s must be a list of server "
                "definitions, not %s",
                fw_obj.region,
                type(expected_settings).__name__,
            )
            sys.exit(1)
    else:
        logging.error(
            "Syslog settings must be a list or dict, got %s",
            type(settings).__name__,
        )
        sys.exit(1)

    results = []
    for settings_container in expected_settings:
        container_name = settings_container['name']
    
        settings_dict = {}
        top_level_keys = ["ServerAddress", "EnableSecureConnection", "Port", "Facility", "SeverityLevel", "Format"]

        for key in top_level_keys:
            if key in settings_container:
                settings_dict[key] = {}
                settings_dict[key]["Name"] = container_name
                settings_dict[key]["Expected"] = settings_container[key]
                if key == "Format" and container_name in actual_settings:
                    if actual_settings[container_name][key] == "3":
                        actual_settings[container_name][key] = "Standard syslog"
                settings_dict[key]["Actual"] = actual_settings[container_name][key] if container_name in actual_settings else f"{container_name} not configured!"

        for settings_category in settings_container['LogSettings']:
            if not settings_category in settings_dict:
                settings_dict[settings_category] = {}
            for setting in settings_container['LogSettings'][settings_category]:
                settings_dict[settings_category][setting] = {}
                settings_dict[settings_category][setting]["Name"] = container_name
                settings_dict[settings_category][setting]["Expected"] = settings_container['LogSettings'][settings_category][setting]
                if container_name in actual_settings:
                    # Fix for v22 where settings under LogSettings > ATP were changed
                    # Makes sure the setting actually exists before trying to access it
                    if setting in actual_settings[container_name]["LogSettings"][settings_category]: 
                        settings_dict[settings_category][setting]["Actual"] = actual_settings[container_name]["LogSettings"][settings_category][setting]
                    else:
                        settings_dict[settings_category][setting]["Actual"] = f"{setting} not available in API version {api_version}"
                else:
                    settings_dict[settings_category][setting]["Actual"] = f"{container_name} not configured!"
        results.append(settings_dict)

    result_dict = {
        "audit_result": "PASS",
        "pass_ct": 0,
        "fail_ct": 0,
        "syslog": {
            "expected": expected_settings,
            "actual": actual_settings
            } 
        }
    for result in results:
        for category in result.keys():
            category_status = "AUDIT_PASS"
            category_expected = []
            category_actual = []

            if category in top_level_keys:
                category_expected.append(f"{result[category]['Expected']}")
                settings_type = result[category]["Name"]
                if not result[category]['Expected'] == result[category]['Actual']:
                    category_actual.append(f"{html_yellow(result[category]['Actual'])}")
                    category_status = "AUDIT_FAIL"
                    result_dict["audit_result"] = "FAIL"
                else:
                    category_actual.append(f"{result[category]['Actual']}")
            else:
                for setting in result[category].keys():
                    category_expected.append(f"{setting}: {result[category][setting]['Expected']}")               
                    settings_type = result[category][setting]["Name"]
                    if result[category][setting]['Actual'] == f"{setting} not available in API version {api_version}":
                        category_actual.append(f"{result[category][setting]['Actual']}")
                        category_status = "AUDIT_PASS"
                        result_dict["audit_result"] = "PASS"
                    elif not result[category][setting]['Expected'] == result[category][setting]['Actual']:
                        category_actual.append(f"{setting}: {html_yellow(result[category][setting]['Actual'])}")
                        category_status = "AUDIT_FAIL"
                        result_dict["audit_result"] = "FAIL"
                    else:
                        category_actual.append(f"{setting}: {result[category][setting]['Actual']}")

            if category_status == "AUDIT_PASS":
                result_dict["pass_ct"] += 1
            elif category_status == "AUDIT_FAIL":
                result_dict["fail_ct"] += 1
            output.append([
                "Syslog",
                "Configure > System services > Log settings",
                f"{settings_type}\n{category}",
                "\n".join(category_expected),
                "\n".join(category_actual),
                html_status(category_status)
            ])

    logging.info(f"{fw_name}: Syslog Result: {result_dict['audit_result']}")

    result_dict["output"] = output

    return result_dict