# Atomic Red Team → Rule Mapping

For each detection, this table lists at least one [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) test that should cause the rule to fire on a properly onboarded test endpoint. Use to validate every rule end-to-end after deployment.

> Always run atomics on an isolated, dedicated test machine. Never on a production host.

| Rule | ATT&CK | Atomic Test ID | Atomic name | Notes |
|---|---|---|---|---|
| EntraID_ImpossibleTravel | T1078.004 | n/a (manual) | — | Sign in from VPN, then within 5 min sign in from a different country's VPN to the same account. |
| EntraID_MFAFatigue | T1621 | n/a (manual) | — | Use Evilginx2 or similar in a lab to issue repeated MFA prompts; user approves on attempt 6+. |
| EntraID_LegacyAuthSuccess | T1110 | n/a (manual) | — | Authenticate via SMTP AUTH (`telnet outlook.office365.com 587`) with a test account that has legacy auth allowed. |
| EntraID_ServicePrincipalCredAdd | T1098.001 | n/a (manual) | — | `New-AzADAppCredential -ObjectId <appId>` adds a client secret to a test app registration. |
| M365_InboxRuleExfil | T1114.003 | T1114.003-1 | New-InboxRule forwarding | Atomic creates an inbox rule that forwards to external address. |
| M365_MassSharePointDownload | T1213.002 | n/a (manual) | — | Use `pnp.powershell` `Get-PnPFile` in loop to download 200 files in <1h from a test SharePoint site. |
| M365_OAuthConsentSuspiciousApp | T1528 | T1528-1 | OAuth consent grant | Atomic walks through illicit-consent flow against a tenant. |
| MDE_LOLBin_Rundll32_Network | T1218.011 | T1218.011-1 | Rundll32 execute JS remote | Spawns rundll32 that pulls remote JS payload. |
| MDE_LOLBin_Rundll32_Network | T1218.011 | T1218.011-23 | rundll32 with Inline VBS | Inline VBScript via rundll32. |
| MDE_MSHTA_RemoteScript | T1218.005 | T1218.005-1 | mshta executes hta over HTTPS | Pulls hta from web. |
| MDE_MSHTA_RemoteScript | T1218.005 | T1218.005-2 | mshta executes javascript: | Inline JS scheme. |
| MDE_PowerShell_EncodedCommand | T1059.001 | T1059.001-1 | Mimikatz via PowerShell EncodedCommand | Long Base64 payload. |
| MDE_PowerShell_EncodedCommand | T1059.001 | T1059.001-3 | PowerShell -enc dropper | Generic encoded dropper. |
| Azure_NSG_OpenToInternet | T1190 | n/a (manual) | — | `az network nsg rule create --source-address-prefixes '*' --destination-port-ranges 3389 --access Allow ...`. |
| Azure_KeyVault_SecretAccessSpike | T1555.005 | n/a (manual) | — | With a test SP, `az keyvault secret show` in a loop over 30+ secrets in a single vault. |
| HUN_FirstSeenASN_PerUser | T1078.004 | n/a (manual) | — | Sign in from a never-before-used VPN provider. |
| HUN_RareProcessPerDevice | T1027 | T1027-7 | XOR-encoded binary | Drop a one-off renamed binary. |
| HUN_AnomalousMailboxForwarding | T1114.003 | T1114.003-2 | Set-Mailbox ForwardingSmtpAddress | Mailbox-level forward to external. |
| HUN_UnsignedBinaryFromTemp | T1204.002 | T1204.002-1 | Execute downloaded file from %TEMP% | |
| HUN_SignInFromDatacenterASN | T1078.004 | n/a (manual) | — | Sign in from an OVH / DigitalOcean VPS. |
| HUN_OfficeChildProcess | T1566.001 | T1566.001-1 | Macro spawns powershell | Open trojanised .docm in a test VM. |
| HUN_NewScheduledTask | T1053.005 | T1053.005-1 | schtasks /create with powershell action | |
| HUN_GuestUserInvitedToPrivilegedGroup | T1098.003 | n/a (manual) | — | Invite a guest, then add to "Application Administrator" role. |
| HUN_DNSRequestsToFreeDynamicDomains | T1071.004 | T1071.004-1 | DNS resolve to dyn-DNS host | `nslookup malware-test.duckdns.org`. |
| HUN_NewSSHConnectionFromInternal | T1021.001 | T1021.001-1 | RDP to remote host | From a workstation, RDP to an internal server. |

## Running atomics

Install Invoke-AtomicRedTeam on a test VM:

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
Invoke-AtomicTest T1059.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1059.001 -TestNumbers 1
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
```

After the atomic runs, expect the corresponding rule to fire within `queryFrequency` (typically 1 hour, faster for near-real-time rules).
