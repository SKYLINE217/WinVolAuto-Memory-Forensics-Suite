# WinVolAuto Plugin Forensics Guide  
**Practical Usage & Investigative Value for Cyber Analysts**  
*Version: 2.3 ‑ February 2025*

---

## 1. How to Use This Guide

1. Open WinVolAuto → load memory dump → select plugins from the tree.  
2. Enable **AI Risk Probability** in *Global Options* for ranked triage.  
3. Review **Results** tab for raw data, **Process Tree** for lineage, **Reports** for PDF/JSON.  
4. Pivot on high-risk PIDs or capabilities listed in the executive summary.

---

## 2. Windows Internal Plugins (Sumit K.K.)

| Plugin | When to Run | What You Get | Next Pivot |
|--------|-------------|--------------|------------|
| **internal.win.cmdline** | Initial triage, any suspected script-based malware | Suspicious commands (-enc, curl, mshta, certutil) with PID & user | Dump PID → malfind / netscan / VT |
| **internal.win.pstree** | After pslist/psscan; spot anomalies | Orphan processes & risky parent/child (word→cmd) | Validate parent legitimacy; dump child |
| **internal.win.kernel_scan** | Suspect rootkit or AV kill | Kernel callback table entries | Cross-check with driverscan; look for unsigned kernel drivers |
| **internal.win.persistence_scan** | Post-breach cleanup or audit | Services loading from %TEMP%, AppData | Obtain binary → signature check → YARA |
| **internal.win.text_scan** | Hunt configs, notes, scripts left in RAM | Path, file name, **20 kB of text content** inline | Keyword search in report; export full dump if IOC found |

**Quick Win**  
Run the **“Quick Triage”** preset (cmdline + pslist + psscan + malfind + netscan + text_scan) → <5 min → AI risk & top 5 suspicious PIDs ready.

---

## 3. Linux Internal Plugins (Sumit K.K.)

| Plugin | When to Run | What You Get | Next Pivot |
|--------|-------------|--------------|------------|
| **internal.linux.pslist** | First 60 s of Linux IR | Processes executing from /tmp, /dev/shm, root shells | Map binary path → ELF headers / VT |
| **internal.linux.bash** | Reconstruct attacker activity | Risky commands (curl, wget, base64, openssl enc, ssh) | Timeline build; correlate with auth logs |
| **internal.linux.check_syscall** | Suspect kernel-level compromise | Count & list of hooked syscalls | Compare with clean syscall table dump |
| **internal.linux.elfs** | Detect runtime-loaded implants | Shared objects in transient directories | Dump ELF → strings / YARA / sigcheck |

**Quick Win**  
Run **internal.linux** group → 3 min → capability summary shows “Execution from /tmp” & “Hooked syscalls” → immediate kernel integrity check.

---

## 4. Core Volatility Plugins – Investigative Context

| Plugin | Key Artifact | Interpretation |
|--------|--------------|----------------|
| **windows.pslist** | Linked EPROCESS list | Baseline of *active* tasks |
| **windows.psscan** | Carved EPROCESS | *Hidden* processes (DKOM) |
| **windows.pstree** | Parent/child pointers | Anomalous lineage (browser→cmd) |
| **windows.malfind** | VADs w/ RWX & no file backing | Injection / hollowed code |
| **windows.netscan** | TCP/UDP endpoints | C2 beacons, data exfil |
| **windows.dlllist** | Loaded modules per process | Legitimate vs injected DLLs |
| **windows.handles** | Open handles (file, reg, mutant) | Mutex names, dropped files |
| **windows.svcscan** | Service records | Persistence via rogue service |
| **windows.filescan** | FILE_OBJECTs | Files touched (even if deleted) |
| **windows.dumpfiles** | Extract file content | Obtain configs or implants |

**Correlation Tip**  
malfind hit + network connection to port 443 with no browser parent → **high-confidence C2**.

---

## 5. macOS Plugins – Baseline & Anomaly

Use **mac.pslist**, **mac.bash**, **mac.check_syscall** for initial triage.  
Add **mac.netstat**, **mac.kextstat**, **mac.launchd** once available via Volatility community.

---

## 6. Report Sections – What Executives Read

1. **Case Metadata** – file hash, size, analyst, timestamp → chain-of-custody.  
2. **Risk Level & Probability** – red / orange / green badge + percentage.  
3. **MITRE Techniques** – T1055, T1564… mapped to findings.  
4. **Malware Capabilities** – “Process Injection”, “Command & Control” with evidence bullets.  
5. **Top Suspicious PIDs** – table of PID vs probability → decide which to dump first.  

---

## 7. Best-Practice Workflow

1. **Acquire** – memory + disk image (if possible).  
2. **Triage** – Quick-Triage preset + AI risk ON.  
3. **Hunt** – internal.text_scan for configs; internal.cmdline for obfuscation.  
4. **Deep-Dive** – dump high-risk PID → `malfind`, `dlllist`, `handles`, `dumpfiles`.  
5. **Report** – export PDF → attach to ticket/audit pack.  

---

## 8. Common Pitfalls & Remedies

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| “No file previews” in text_scan | Dump contains no FILE_OBJECTs or regex mismatch | Lower regex filter; re-acquire with more memory pages |
| AI risk = 0 % | Plugins not enabled or no suspicious features | Re-run with malfind + netscan + cmdline |
| Parse error | Volatility output format changed | Update vol3; fallback parser handles 99 % cases |
| UI freeze | Forgot QThread | Already handled – report bug if seen |

---

## 9. Training & Certification Alignment

| Cert | WinVolAuto Coverage |
|------|---------------------|
| GCFA | Memory forensics, timeline, malware detection ✅ |
| GNFA | Network artifacts, C2 identification ✅ |
| OSCP | Process injection, persistence enumeration ✅ |
| CISSP | Audit-ready reports, hash integrity ✅ |

---

## 10. Summary Cheat-Sheet

- **Enable AI** → get ranked PIDs.  
- **Run internal plugins** → 4-min triage.  
- **Export PDF** → court-ready evidence.  
- **Pivot on capabilities** → speak business risk.  

*Memory never lies — WinVolAuto makes sure you hear the truth in time.*