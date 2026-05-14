# Playbook: AutoEnrichDisableUser

Triggers on a new Microsoft Sentinel incident. For every IP entity, queries VirusTotal and AbuseIPDB and tracks the maximum reputation confidence across the incident. If confidence is at or above the configurable threshold (default 80), the playbook disables every Entra ID user entity on the incident and posts an audit comment back to Sentinel. Below threshold, it still posts the enrichment results as a comment for the analyst — no auto-action.

## Required API connections

Deploy and authorise these once in the resource group before deploying the playbook:

- `azuresentinel` — Microsoft Sentinel
- `azuread` — Microsoft Entra ID (account that has User Administrator at minimum)
- `virustotal` — VirusTotal v3
- `abuseipdb` — AbuseIPDB v2

## Deploy

```bash
az deployment group create \
  --resource-group <rg> \
  --template-file azuredeploy.json \
  --parameters PlaybookName=AutoEnrichDisableUser \
               DisableUserConfidenceThreshold=80
```

Then bind it to incidents via an **automation rule** in Sentinel (Sentinel → Automation → Create automation rule → "Run playbook").

## Why a confidence threshold and not full-auto disable

False positives on user disablement are very expensive (loss of legitimate access, support burden). Forcing a reputation-confidence floor and posting an audit comment lets the playbook double as both an action *and* an enrichment, so the analyst gets value either way.
