# =============================================================
# File: lateral-movement-analysis.md
# =============================================================

# Internal Lateral Movement PCAP Analysis Report

**Analyst:** Amoah Reinhard | **Date:** 2025-06-19 | **Threat Level:** CRITICAL

---

## Executive Summary

Internal reconnaissance and lateral movement was detected originating from an already-compromised
host (`192.168.1.42`). The attacker leveraged SMB, WMI, and PsExec to move laterally across
the internal network, compromising 4 additional hosts within 18 minutes. Credential spraying
via NTLM was detected against 22 internal hosts. Post-compromise, a Cobalt Strike beacon
was established on each newly compromised host.

**MITRE Techniques:** T1021.002, T1047, T1569.002, T1110.003, T1550.002, T1018, T1135

---

## Network Indicators

### Initial Compromised Host (pivot point)
| Field | Value |
|-------|-------|
| IP | 192.168.1.42 |
| Hostname | DEV-LAPTOP-3 |
| User | jsmith (domain admin) |

### Laterally Compromised Hosts
| IP | Hostname | Method | Time |
|----|----------|--------|------|
| 192.168.1.20 | FILE-SERVER-1 | PsExec via SMB | 09:47:15 |
| 192.168.1.25 | HR-PC-05 | WMI Win32_Process | 09:52:30 |
| 192.168.1.30 | FINANCE-WS-2 | SMB + service install | 09:58:44 |
| 192.168.1.35 | DC-01 | Pass-the-Hash + DCSync | 10:05:00 |

---

## Zeek Log Findings

### conn.log — Reconnaissance Phase

**SMB Network Scan:**
```
Time: 09:45:00 – 09:45:30 (30 seconds)
192.168.1.42 → 192.168.1.0/24:445
Hosts contacted: 24 in 30 seconds
→ SMB_Multi_Host_Scan detected (threshold: 5 hosts in 2 min)
```

**WMI/DCOM Probe:**
```
192.168.1.42 → 192.168.1.1:135    DCOM port probe
192.168.1.42 → 192.168.1.20:135   DCOM — WMI connection
192.168.1.42 → 192.168.1.25:135   DCOM — WMI connection
```

### smb-monitor.log — Admin Share Access + PsExec

**Admin Share Access:**
```
src_ip          dst_ip          share    action               indicator
192.168.1.42    192.168.1.20    ADMIN$   ADMIN_SHARE_ACCESS   ALERT
192.168.1.42    192.168.1.20    C$       ADMIN_SHARE_ACCESS   ALERT
192.168.1.42    192.168.1.30    ADMIN$   ADMIN_SHARE_ACCESS   ALERT
```

**PsExec Binary Written:**
```
src_ip          dst_ip          path              action          indicator
192.168.1.42    192.168.1.20    PSEXESVC.exe      PSEXEC_BINARY   CRITICAL
192.168.1.42    192.168.1.30    PSEXESVC.exe      PSEXEC_BINARY   CRITICAL
```

### lateral-movement.log — WMI Execution
```
src_ip          dst_ip          port  indicator         detail
192.168.1.42    192.168.1.25    135   WMI_REMOTE_EXEC   WMI/DCOM Win32_Process Create
192.168.1.42    192.168.1.30    135   WMI_REMOTE_EXEC   WMI/DCOM Win32_Process Create
```

### Pass-the-Hash (NTLM) Detection
```
From smb2 traffic analysis:
192.168.1.42 → 192.168.1.35:445  NTLM Type1 (no username — PTH indicator)
→ 22 authentication attempts to 22 hosts in 3 minutes
→ Auth_Spray detected (threshold: 5 hosts)
```

---

## Suricata Alerts

| SID | Signature | Hits |
|-----|-----------|------|
| 9001001 | LATERAL MOVEMENT SMB Multi-Host Scan | 1 |
| 9001002 | LATERAL MOVEMENT PsExec Service Binary | 2 |
| 9001004 | LATERAL MOVEMENT WMI Remote Execution | 3 |
| 9001005 | LATERAL MOVEMENT Pass-the-Hash NTLM Auth | 22 |
| 9001006 | LATERAL MOVEMENT Remote Service Creation | 2 |
| 9001008 | LATERAL MOVEMENT DCOM WMI Win32_Process | 2 |

**Total Lateral Movement Alerts: 32**

---

## IOCs Extracted

**Internal IPs involved:**
```
192.168.1.42    # Initial pivot host (jsmith)
192.168.1.20    # FILE-SERVER-1 — PsExec'd
192.168.1.25    # HR-PC-05 — WMI Execute
192.168.1.30    # FINANCE-WS-2 — SMB + service
192.168.1.35    # DC-01 — Pass-the-Hash
```

**Indicators:**
```
PSEXESVC.exe written to ADMIN$ share on 2 hosts
NTLM authentication spray to 22 hosts from single source
WMI Win32_Process Create on 3 internal hosts
DCSync suspected on DC-01 (Kerberos traffic spike post-PTH)
```

---

## Attack Timeline

```
09:45:00  SMB network scan — 24 hosts in 30 seconds (recon)
09:45:30  Admin share enumeration — \\192.168.1.20\ADMIN$ accessed
09:45:35  C$ share accessed — \\192.168.1.20\C$
09:47:00  PsExec binary written — \\192.168.1.20\ADMIN$\PSEXESVC.exe
09:47:15  Remote shell established on FILE-SERVER-1
09:52:00  WMI execution on HR-PC-05 — cmd.exe spawned
09:52:30  Cobalt Strike beacon installed on HR-PC-05
09:55:00  NTLM credential spray — 22 hosts in 3 minutes (Pass-the-Hash)
09:58:44  PsExec to FINANCE-WS-2 — second PsExec deployment
10:05:00  Pass-the-Hash against DC-01 — DOMAIN ADMIN LEVEL ACCESS
10:05:30  Suspected DCSync — Kerberos TGS flood to DC-01
10:06:00  All domain user hashes likely extracted
```

---

## Detection Recommendations

1. **IMMEDIATE**: Isolate DC-01 — full domain compromise suspected, initiate IR
2. Reset ALL domain account passwords — attacker likely has full domain hash dump
3. Isolate all 5 affected hosts for forensic imaging
4. Audit all group memberships and service accounts — attacker may have created backdoor accounts
5. Enable SMB signing — prevents NTLM relay and Pass-the-Hash attacks
6. Implement credential guard on all Windows endpoints
7. Restrict admin shares (C$, ADMIN$) via GPO — only Domain Controllers should access
8. Deploy LAPS (Local Administrator Password Solution) to prevent credential reuse
9. Alert on any single host initiating SMB to >3 internal hosts in 2 minutes
10. Block PsExec from non-admin subnets via firewall and AppLocker
