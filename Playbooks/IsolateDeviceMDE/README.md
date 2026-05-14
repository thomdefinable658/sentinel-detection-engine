# Playbook: IsolateDeviceMDE

Triggered on Sentinel incident creation. For every Host entity that carries an MDE device ID, calls the MDE `machineActions/isolate` API and posts an audit comment back to Sentinel.

**Isolation modes:**
- `Selective` (default): blocks all outbound network EXCEPT Defender + Outlook + Teams. Lets the user continue limited comms while you investigate.
- `Full`: total network block. Use for confirmed ransomware staging.

## Required permissions

App registration with the following Microsoft Defender for Endpoint API permissions, **admin-consent granted**:
- `Machine.Isolate`
- `Machine.Read.All`

## Deploy

```bash
az deployment group create \
  --resource-group <rg> \
  --template-file azuredeploy.json \
  --parameters PlaybookName=IsolateDeviceMDE IsolationType=Selective
```

Bind to incidents via Sentinel **Automation rule**: trigger = `Incident created`, condition = `Analytic rule name contains MDE_`, action = run this playbook.

## Reversal

`Unisolate` the device from MDE portal → Device → Actions → **Release from isolation**, or run the inverse Graph API call. Always document reversal in the incident comment.
