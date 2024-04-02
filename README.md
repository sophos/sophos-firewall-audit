# Firewall Audit

## Environment Variables

If using HashiCorp Vault to retrieve firewall credentials:
```bash
VAULT_MOUNT_POINT = HashiCorp Vault Mount Point (ex. kv)
VAULT_SECRET_PATH = HashiCorp Vault Secret path
VAULT_SECRET_KEY = HashiCore Vault Secret Key
ROLEID = HashiCorp Vault Role ID
SECRETID = HashiCorp Vault Secret ID
```

If not using HashiCorp Vault:
```bash
FW_USERNAME = Firewall username
FW_PASSWORD = Firewall password
```

If using Nautobot as inventory:
```bash
NAUTOBOT_URL = Nautobot URL
NAUTOBOT_TOKEN = Nautobot API Token
```