""" Sophos Firewall Audit - auth.py

Copyright 2024 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
"""

import os
import sys
import logging
import hvac

def get_credential(mount_point, secret_path, key):
    """Get a credential from Hasicorp Vault.

    Args:
        mount_point (str): secret engine name
        secret_path (str): path to the secret
        key (str): Lookup value in the secret store
    """
    client = hvac.Client()
    client.auth.approle.login(
    role_id=str(os.environ['ROLEID']),
    secret_id=str(os.environ['SECRETID']),
)
    try:
        read_secret_result = client.secrets.kv.v1.read_secret(
        path=secret_path,
        mount_point=mount_point,
        )
    except Exception as err:
        logging.error(f"Error getting credential from Vault: {err}")
        sys.exit(1)
    try:
        return read_secret_result['data'][key]
    except KeyError:
        logging.error(f"The key '{key}' was not found at path '{secret_path}'")
        sys.exit(1)