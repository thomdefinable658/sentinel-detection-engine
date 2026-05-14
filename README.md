# sentinel-hunt-pack

> Detection-as-code for **Microsoft Sentinel** — 12 analytic rules, 10 hunting queries, an L3 triage workbook, a Logic App playbook, ATT&CK Navigator coverage, and Atomic Red Team validation mapping. Every rule is CI-validated.

**Author:** Sandeep Mothukuri — SOC L3 / Incident Response
**Repo:** [`sandeepmothukuri/sentinel-hunt-pack`](https://github.com/sandeepmothukuri/sentinel-hunt-pack)

---

## Why this exists

Most public Sentinel content is either (a) a single hand-written query in a blog post, or (b) the full Microsoft community repo with thousands of rules and no curation. This pack sits in the middle: a **focused, curated set of high-signal detections** an L3 analyst would actually deploy on day one, with the engineering rigour (schema validation, ATT&CK mapping, ART tests) of a production detection-engineering team.

## What's inside

| Area | Count | Folder |
|---|---|---|
| Scheduled analytic rules | 12 | [`Detections/`](Detections/) |
| Hunting queries | 10 | [`Hunting Queries/`](Hunting%20Queries/) |
| Workbook (L3 Triage Dashboard) | 1 | [`Workbooks/`](Workbooks/) |
| Logic App playbook | 1 | [`Playbooks/`](Playbooks/) |
| ATT&CK Navigator layer | 1 | [`attack-navigator/`](attack-navigator/) |
| Atomic Red Team mapping | 22 tests | [`tests/atomics.md`](tests/atomics.md) |
| CI validation workflow | 1 | [`.github/workflows/validate.yml`](.github/workflows/validate.yml) |

### Coverage snapshot

- **Tactics covered:** Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Collection, Command & Control, Exfiltration
- **Techniques covered:** 18 unique ATT&CK techniques (see [`coverage.md`](coverage.md))
- **Data sources:** Microsoft Entra ID, Microsoft 365 (Exchange, SharePoint, OAuth), Microsoft Defender for Endpoint, Azure Activity, Azure Key Vault

## Rules at a glance

### Identity & Cloud Identity (Entra ID)
- `EntraID_ImpossibleTravel.yaml` — geo-distance + time-delta sign-in correlation
- `EntraID_MFAFatigue.yaml` — repeated MFA prompts followed by success
- `EntraID_LegacyAuthSuccess.yaml` — successful auth over legacy protocols
- `EntraID_ServicePrincipalCredAdd.yaml` — credential added to SP outside CI/CD allow-list

### Microsoft 365
- `M365_InboxRuleExfil.yaml` — auto-forward / delete inbox rule creation
- `M365_MassSharePointDownload.yaml` — anomalous file download volume per user
- `M365_OAuthConsentSuspiciousApp.yaml` — consent to non-verified publisher with high-risk scopes

### Endpoint (Defender for Endpoint)
- `MDE_LOLBin_Rundll32_Network.yaml` — rundll32 making external network connections
- `MDE_MSHTA_RemoteScript.yaml` — mshta executing remote HTA/script
- `MDE_PowerShell_EncodedCommand.yaml` — long Base64 -EncodedCommand invocations

### Azure Infrastructure
- `Azure_NSG_OpenToInternet.yaml` — NSG rule opening port to 0.0.0.0/0
- `Azure_KeyVault_SecretAccessSpike.yaml` — abnormal secret-access volume per identity

## Hunting queries (10)

Hypothesis-driven hunts in [`Hunting Queries/`](Hunting%20Queries/). Examples:
- First-seen ASN per user (sign-in baseline drift)
- Rare process per device parent-child chain
- Anomalous mailbox forwarding to external domain
- Unsigned binaries executing from `%TEMP%`
- Sign-in from datacenter ASN (Tor/VPS proxying)

## Deployment

Three deployment paths, in order of recommended:

### 1. Sentinel Repositories (GitOps, recommended)
This repo follows the official `Azure/Azure-Sentinel` folder schema, so you can connect it directly:

1. Sentinel → **Repositories** → **Add new**
2. Connect this GitHub repo
3. Select `main` branch
4. Sentinel pulls and deploys all 12 rules + 10 hunts + 1 workbook on every push

Docs: <https://learn.microsoft.com/azure/sentinel/ci-cd>

### 2. Manual import
Each YAML file is a self-contained Sentinel rule. Paste the `query:` block into Sentinel → Analytics → New scheduled rule, copy the metadata, save.

### 3. ARM / Bicep
The Logic App playbook ships as ARM in [`Playbooks/AutoEnrichDisableUser/azuredeploy.json`](Playbooks/AutoEnrichDisableUser/azuredeploy.json). Deploy via:

```bash
az deployment group create \
  --resource-group <rg> \
  --template-file Playbooks/AutoEnrichDisableUser/azuredeploy.json
```

### Free tier setup

You can run the full pack on a brand-new Azure tenant with **$0 spend** for the first 30 days. See [`docs/free-tier-setup.md`](docs/free-tier-setup.md).

## Validation (CI)

GitHub Actions runs on every PR ([`.github/workflows/validate.yml`](.github/workflows/validate.yml)):

1. **YAML schema lint** — every rule conforms to the Sentinel rule schema
2. **KQL parse check** — queries parse without syntax errors
3. **ATT&CK ID validation** — every `tactics:` / `relevantTechniques:` value exists in the current ATT&CK matrix
4. **Markdown link check** — no broken internal links

## Testing with Atomic Red Team

Each detection is mapped to one or more [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) tests that should trigger it. See [`tests/atomics.md`](tests/atomics.md).

Example:
```
T1059.001 (PowerShell)  →  MDE_PowerShell_EncodedCommand.yaml  →  Atomic Test-1, Test-3
```

## Repo layout

```
sentinel-hunt-pack/
├── Detections/                 # 12 analytic rules (Sentinel YAML schema)
├── Hunting Queries/            # 10 hunts
├── Workbooks/
│   └── L3-Triage-Dashboard.json
├── Playbooks/
│   └── AutoEnrichDisableUser/
│       ├── azuredeploy.json
│       └── README.md
├── attack-navigator/
│   └── layer.json              # drop into mitre-attack.github.io/attack-navigator
├── tests/
│   └── atomics.md              # ART test ID → rule mapping
├── scripts/
│   └── generate_coverage.py    # regenerates coverage.md + Navigator layer
├── docs/
│   ├── free-tier-setup.md
│   └── images/
├── .github/workflows/
│   └── validate.yml
├── coverage.md                 # auto-generated ATT&CK matrix
└── README.md
```

## Roadmap

- [ ] Add AWS GuardDuty / CloudTrail analog pack (`aws-hunt-pack`)
- [ ] Add Defender for Cloud Apps (MCAS) coverage
- [ ] Notebook (`.ipynb`) IR playbook for one of the detections fired end-to-end
- [ ] Sigma → KQL conversion mapping for portability

## License

[MIT](LICENSE)
