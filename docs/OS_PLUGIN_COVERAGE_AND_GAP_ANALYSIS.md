# WinVolAuto – OS Plugin Coverage & Gap Analysis  
**Comparative Assessment Across Windows, Linux, macOS**  
*Version: 2.3 ‑ February 2025*

---

## 1. Purpose

Provide auditors, architects, and DFIR managers with:
- A clear inventory of **current plugin coverage** per operating system inside WinVolAuto.  
- Identification of **forensic gaps** that still require manual Volatility commands.  
- A **prioritised action plan** to achieve feature parity and exceed commercial-tool baseline.

---

## 2. Methodology

- **Baseline**: Plugins dynamically discovered from a clean Volatility 3.5.2 installation.  
- **Mapping**: Each plugin mapped to MITRE ATT&CK technique and forensic goal (Execution, Persistence, Defense-Evasion, C2, Impact, etc.).  
- **Gap Score**: (1 − covered_techniques ÷ total_techniques) × 100 % per OS.

---

## 3. Windows – Current Coverage

| Category | Plugin | Technique | Status | Evidence Output |
|----------|--------|-----------|--------|-----------------|
| **Process Baseline** | windows.pslist    | – | ✅ Default | Running processes |
| **Hidden Processes** | windows.psscan    | T1564.001 | ✅ Default | Unlinked EPROCESS |
| **Hierarchy**        | windows.pstree    | – | ✅ Internal | Parent/child tree |
| **Command Line**     | windows.cmdline   | T1059.001 | ✅ Internal | Encoded PS, curl, mshta |
| **Code Injection**   | windows.malfind   | T1055 | ✅ Default | RWX private pages |
| **Network**          | windows.netscan   | T1071.001 | ✅ Default | TCP/UDP endpoints |
| **Modules**          | windows.dlllist   | T1129 | ✅ Default | Loaded DLLs |
| **Handles**          | windows.handles   | – | ✅ Default | Open files, mutants |
| **Services**         | windows.svcscan   | T1543.003 | ✅ Default + Internal | Temp-path services |
| **Callbacks**        | windows.callbacks | T1014 | ✅ Internal | Kernel callbacks |
| **File Extraction**  | windows.dumpfiles | – | ✅ Internal | ≤20 kB text preview |

**Gap Score**: 18 % (missing driver/module deep-dive, registry persistence, scheduled tasks, WMI, VAD injection maps).

---

## 4. Linux – Current Coverage

| Category | Plugin | Technique | Status | Evidence Output |
|----------|--------|-----------|--------|-----------------|
| **Process Baseline** | linux.pslist        | – | ✅ Default | Task list |
| **Hidden Processes** | linux.psscan        | T1564.001 | ❌ Not wired | – |
| **Shell History**    | linux.bash          | T1059.004 | ✅ Internal | curl, wget, base64 |
| **Syscall Hooks**    | linux.check_syscall | T1014 | ✅ Internal | Hooked syscall count |
| **ELF Modules**      | linux.elfs          | T1129 | ✅ Internal | /tmp, /dev/shm .so |
| **Network**          | linux.netstat       | T1071.001 | ❌ Not wired | – |
| **Open Files**       | linux.lsof          | – | ❌ Not wired | – |
| **Kernel Modules**   | linux.lsmod         | T1547.006 | ❌ Not wired | – |
| **Persistence**      | linux.cron, systemd | T1053 | ❌ Not wired | – |

**Gap Score**: 62 % (network, persistence, hidden processes, kernel-module trust).

---

## 5. macOS – Current Coverage

| Category | Plugin | Technique | Status | Evidence Output |
|----------|--------|-----------|--------|-----------------|
| **Process Baseline** | mac.pslist        | – | ✅ Default | Task list |
| **Shell History**    | mac.bash          | T1059.004 | ✅ Default | History entries |
| **Syscall Hooks**    | mac.check_syscall | T1014 | ✅ Default | Hooked syscall count |
| **Network**          | mac.netstat       | T1071.001 | ❌ Not wired | – |
| **Kext**             | mac.kextstat      | T1547.006 | ❌ Not wired | – |
| **Launchd**          | mac.launchd       | T1543.004 | ❌ Not wired | – |
| **Code Signing**     | mac.codesign      | T1553.001 | ❌ Not wired | – |

**Gap Score**: 71 % (network, kernel extensions, launch-daemons, code-sign verification).

---

## 6. Cross-OS Forensic Gaps (High Impact)

| Gap | Windows | Linux | macOS | Recommended Plugin |
|-----|---------|-------|-------|--------------------|
| **Hidden Process Detection** | Covered | Missing | Missing | `linux.psscan`, `mac.psscan` |
| **Network Artifacts**        | Covered | Missing | Missing | `linux.netstat`, `mac.netstat` |
| **Kernel-Module Integrity**  | Partial | Missing | Missing | `windows.driverscan`, `linux.lsmod`, `mac.kextstat` |
| **Persistence Mechanisms**   | Partial | Missing | Missing | Registry + Scheduled-Tasks, systemd/cron, LaunchAgents/Daemons |
| **Memory-Map Injection**     | Partial | Missing | Missing | VAD walk, `/proc/*/maps`, mach VM regions |
| **Code-Sign Trust**          | Manual  | Missing | Missing | Authenticode, ELF sig, macOS notarization |
| **Unified Timeline**         | Missing | Missing | Missing | Cross-plugin timestamp correlation engine |

---

## 7. Prioritised Action Plan

### Priority 1 (Q2 2025) – Triage Blockers
1. Wire `linux.psscan` & `mac.psscan` → close hidden-process gap.  
2. Add `linux.netstat` & `mac.netstat` → surface C2 channels.  
3. Integrate `windows.driverscan` + signature trust check → kernel rootkit detection.

### Priority 2 (Q3 2025) – Persistence & Trust
1. Registry persistence plugins (`printkey` on Run, Services, Tasks) for Windows.  
2. systemd/cron parsers for Linux; launchd parser for macOS.  
3. Authenticode / ELF-sig / macOS notarization validation → unsigned binary risk.

### Priority 3 (Q4 2025) – Advanced Analytics
1. **Unified Timeline Engine** – correlate timestamps from pslist, netscan, malfind, registry, bash.  
2. **Memory-Map Injection Maps** – per-process VAD (Windows), `/proc/*/maps` (Linux), mach VM (macOS).  
3. **STIX 2.1 Export** – package indicators per OS for threat-intel feeds.

---

## 8. Implementation Notes

- **Dynamic Discovery**: Use `PluginDiscovery` class to locate OS-specific plugins at runtime; no hard-coded lists.  
- **Risk Integration**: Feed new plugin outputs into `RiskAnalyzer` for feature extraction and MITRE mapping.  
- **Capability Evidence**: Add new capability categories (e.g., “Kernel Persistence”, “Code-Sign Evasion”) in `CapabilityAnalyzer`.  
- **Report Sections**: Auto-generate OS-specific subsections in PDF to avoid clutter.

---

## 9. Success Metrics

| Milestone | Metric | Target |
|-----------|--------|--------|
| Hidden-process coverage   | Gap Score reduction | <10 % per OS |
| Network artifact coverage | Plugin availability | 100 % (netstat wired) |
| Persistence coverage      | Techniques detected | ≥8 per OS |
| Kernel integrity          | Driver/kext trust check | 100 % for Windows & macOS |
| Timeline correlation      | Events/sec parsed | >10 k with <2 min delay |

---

## 10. Conclusion

WinVolAuto already exceeds most open-source memory forensics tools for **Windows triage**.  
Closing the identified gaps will deliver **cross-platform parity** and **enterprise-grade depth**, positioning WinVolAuto as the **reference open-source platform** for memory-based threat detection and compliance evidence.

*Memory never lies — WinVolAuto makes sure you hear the truth on every operating system.*