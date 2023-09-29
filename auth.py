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