<h1 align="center">
  DomainBreach
  <br>
</h1>

<p align="center">
  A PowerShell lab tool that deliberately misconfigures Active Directory to create a realistic,
  fully rollback-able vulnerable environment for security testing, red team practice, and
  PingCastle / BloodHound training.
</p>

---

### Inspiration

DomainBreach was inspired by and built upon **[vulnerable-AD](https://github.com/safebuffer/vulnerable-AD)**
by [@safe_buffer](https://twitter.com/safe_buffer). The original project pioneered the idea of a
single-script AD lab with randomized misconfigurations and showed how much damage a handful of
PowerShell lines could do to a clean domain. Core user/group population logic and several of the
original attack modules are derived from that work. DomainBreach extends the foundation with
deeper PingCastle coverage, a redesigned categorized menu, and full rollback support for every module.

---

### Requirements

- Windows Server with Active Directory Domain Services installed and promoted to DC
- Run as Domain Administrator
- PowerShell 5.1+

---

### Features

- **19 independent vulnerability modules** — run all at once or pick individually from the menu
- **Randomized targeting** — different users and groups are affected on every run
- **Full rollback** — every change is tracked in a JSON state file and can be cleanly reversed
- **PingCastle-aligned** — each module maps to specific PingCastle rule IDs with score estimates
- **Categorized menu** — modules grouped by attack category and sorted by detection score

---

### Vulnerability Modules

#### Kerberos Attacks

| Module | PingCastle Rule | What It Does |
|---|---|---|
| KRBTGT Password Age | `A-Krbtgt` (~50 pts) | Backdates KRBTGT `pwdLastSet` by 5 years |
| Privileged Kerberoasting + Schema Admins | `P-SchemaAdmin`, `P-ServiceDomainAdmin`, `P-Kerberoasting` (~40 pts) | Creates a Domain Admin service account with a weak-password SPN; adds a random user to Schema Admins |
| Unconstrained Delegation | `A-UnconstrainedDelegation`, `P-UnconstrainedDelegation` (~30 pts) | Sets `TrustedForDelegation` on random users and creates a delegated computer account |
| AS-REP Roasting | `S-NoPreAuth` (~30 pts) | Disables Kerberos pre-authentication on 1–6 random users |
| Kerberoasting | `P-Kerberoasting` (~25 pts) | Creates service accounts with SPNs and weak passwords |

#### Domain Compromise

| Module | PingCastle Rule | What It Does |
|---|---|---|
| DCSync Rights | — (~30 pts) | Grants DS-Replication extended rights to 1–6 unprivileged users |
| Bad ACLs | — (~20 pts) | Grants GenericAll / WriteDACL / WriteOwner / WriteProperty on group objects |
| AdminSDHolder Abuse | `A-AdminSDHolder` (~18 pts) | Grants GenericAll on the AdminSDHolder object; ACE propagates to all protected accounts via SDProp |
| DnsAdmins | `P-DNSAdmin` (~15 pts) | Adds random users and a group to the DnsAdmins group |

#### Legacy Protocols & Services

| Module | PingCastle Rule | What It Does |
|---|---|---|
| Legacy Protocols | `A-LMHashAuthorized`, `A-NullSession`, `S-SMBv1` (~35 pts) | Enables LM hash storage, null sessions, and SMBv1 server via registry |
| LDAP Signing + Print Spooler | `A-LDAPSigningDisabled`, `A-DCLdapSign`, `A-DCSpooler` (~25 pts) | Disables LDAP server integrity signing; starts Print Spooler on the DC |
| SMB Signing Disabled | `A-SMB2SignatureNotEnabled` (~15 pts) | Disables SMB client signing requirement |

#### Account Weaknesses

| Module | PingCastle Rule | What It Does |
|---|---|---|
| Guest + Pre-Windows 2000 | `A-Guest`, `A-PreWin2000AuthenticatedUsers` (~20 pts) | Enables the Guest account; adds Authenticated Users to the Pre-Windows 2000 Compatible Access group |
| Reversible Encryption + DES | `A-ReversiblePwd`, `S-DesEnabled` (~18 pts) | Enables reversible password encryption and DES Kerberos encryption type on random users |
| SID History | `S-SIDHistory` (~12 pts) | Adds fabricated foreign-domain SID history to random users |
| Password Never Expires | `S-PwdNeverExpires` (~12 pts) | Sets `PasswordNeverExpires` on 5–15 random users |
| Password in Description | — (~8 pts) | Stores plaintext passwords in AD user Description fields |
| Default Password | — (~8 pts) | Sets `Changeme123!` as the password on random users |
| Password Spraying | — (~8 pts) | Sets the same weak password (`ncc1701`) on multiple users |

---

### Usage

```powershell
# Optional: install AD DS and promote to DC first
.\domainbreach.ps1 -Setup -DomainName "breach.local"

# Populate the domain with all 19 vulnerability modules
.\domainbreach.ps1 -Populate -DomainName "breach.local"

# Run interactively with the categorized module menu
.\domainbreach.ps1 -Menu

# Roll back all changes using the generated state file
.\domainbreach.ps1 -Rollback -StateFile ".\DomainBreach-State-breach.local-20260405-120000.json"
```

Or dot-source and call directly:

```powershell
. .\domainbreach.ps1
Invoke-DomainBreach -UsersLimit 100 -DomainName "breach.local"
```

---

### PingCastle Integration

Run [PingCastle](https://www.pingcastle.com/) against your lab DC after populating to see the
risk score light up. DomainBreach targets rules across all four PingCastle categories:
**Anomalies**, **Privileged Accounts**, **Stale Objects**, and **Trusts**.

```powershell
.\PingCastle.exe --healthcheck --server breach.local
```

---

### Rollback

Every run generates a state file (`DomainBreach-State-<domain>-<timestamp>.json`). Pass it to
`-Rollback` to cleanly undo all changes — including registry modifications, group memberships,
ACL entries, account flags, and any created objects.

---

### Credits

Original concept and core code: **[vulnerable-AD](https://github.com/safebuffer/vulnerable-AD)** by [@safe_buffer](https://twitter.com/safe_buffer)
