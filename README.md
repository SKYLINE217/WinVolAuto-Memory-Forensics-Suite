<div align="center">

<!-- Animated Header Banner -->
<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0D1117,50:7B2FBE,100:00D4AA&height=220&section=header&text=WinVolAuto&fontSize=52&fontColor=FFFFFF&animation=fadeIn&fontAlignY=35&desc=Professional%20Memory%20Forensics%20Suite%20%E2%80%A2%20Powered%20by%20Volatility%203&descSize=17&descAlignY=55&descColor=94A3B8" width="100%" />

<!-- Animated Typing SVG -->
<a href="https://github.com/SKYLINE217/WinVolAuto-Memory-Forensics-Suite">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=22&duration=3000&pause=1000&color=7B2FBE&center=true&vCenter=true&multiline=true&repeat=true&width=750&height=80&lines=Deep-Dive+Memory+Forensics+Without+the+Command+Line;Windows+%E2%80%A2+Linux+%E2%80%A2+macOS+Memory+Analysis;AI+Risk+Scoring+%7C+MITRE+ATT%26CK+Mapping+%7C+Auto+Reports" alt="Typing SVG" />
</a>

<br/>

<!-- Badges Row 1 — Stack -->
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PyQt6](https://img.shields.io/badge/PyQt6-GUI-41CD52?style=for-the-badge&logo=qt&logoColor=white)
![Volatility3](https://img.shields.io/badge/Volatility-3-7B2FBE?style=for-the-badge&logo=virustotal&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-Forensics-0078D4?style=for-the-badge&logo=windows&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Forensics-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![AI](https://img.shields.io/badge/AI-Risk%20Scoring-FF6B6B?style=for-the-badge&logo=openai&logoColor=white)
![License](https://img.shields.io/badge/License-Research%20Only-FFD700?style=for-the-badge)

<br/>

<!-- Badges Row 2 — Quick Links -->
[![Features](https://img.shields.io/badge/🚀_Key-Features-7B2FBE?style=flat-square)](#-key-features)
[![Architecture](https://img.shields.io/badge/🏗️_Architecture-Docs-00D4AA?style=flat-square)](#️-architecture--workings)
[![Install](https://img.shields.io/badge/🛠️_Installation-Guide-4D6AF5?style=flat-square)](#️-installation--setup)
[![Plugins](https://img.shields.io/badge/🧩_Plugin-Reference-FF6B6B?style=flat-square)](#-the-dashboard-a-detailed-tour)
[![Legal](https://img.shields.io/badge/⚖️_Legal-Disclaimer-F59E0B?style=flat-square)](#️-legal-disclaimer)

</div>

---

> [!CAUTION]
> **Authorization Required** — WinVolAuto is a specialized tool intended **exclusively** for authorized security research, digital forensics, and incident response. You **must** have explicit written permission to capture and analyze memory from any target system. The creators disclaim all liability for unauthorized use. Misuse may violate federal law (CFAA) and equivalent international statutes.

---

## 🌐 Overview

<table>
<tr>
<td width="58%">

**WinVolAuto** is a powerful, user-friendly desktop application designed to make memory forensics simple, accessible, and highly efficient. Built on top of the industry-standard **Volatility 3** framework, it provides a sleek, modern interface for analyzing memory dumps from Windows, Linux, and Mac systems — **no command line required**.

Whether you are a seasoned malware analyst, a security researcher, or a student learning digital forensics, WinVolAuto handles the complexity for you, allowing you to focus on the results.

**By the Numbers:**

| | |
|---|---|
| 🧩 **Plugin Engine** | Dynamic — discovers every installed plugin automatically |
| 🖥️ **OS Support** | Windows · Linux · macOS memory dumps |
| 🤖 **AI Risk Scoring** | Per-PID probability + MITRE ATT&CK mapping |
| 📄 **Report Formats** | JSON + PDF with safe table rendering |
| ⚡ **Execution Model** | Non-blocking async via `QThread` |

</td>
<td width="42%">

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': {'primaryColor': '#7B2FBE', 'edgeLabelBackground':'#0D1117'}}}%%
graph TD
    A[🧠 Memory Dump] -->|Load| B[WinVolAuto UI]
    B -->|Discover| C[Plugin Engine]
    C -->|Execute| D[Volatility 3 Core]
    D -->|JSON Stream| E[Result Parser]
    E --> F[📊 Results Table]
    E --> G[🌳 Process Tree]
    E --> H[🤖 AI Risk Analyzer]
    H -->|MITRE Map| I[📑 PDF Report]

    style A fill:#1a1a2e,stroke:#7B2FBE,color:#fff
    style B fill:#1a1a2e,stroke:#00D4AA,color:#fff
    style C fill:#1a1a2e,stroke:#4D6AF5,color:#fff
    style D fill:#1a1a2e,stroke:#FF6B6B,color:#fff
    style E fill:#1a1a2e,stroke:#00D4AA,color:#fff
    style F fill:#1a1a2e,stroke:#41CD52,color:#fff
    style G fill:#1a1a2e,stroke:#F59E0B,color:#fff
    style H fill:#1a1a2e,stroke:#EE4C2C,color:#fff
    style I fill:#1a1a2e,stroke:#7B2FBE,color:#fff
```

</td>
</tr>
</table>

---

## 🚀 Key Features

<div align="center">

| Feature | Description |
|:---:|:---|
| 🖥️ **Professional Dark UI** | Crafted dark-themed interface (`#1e1e1e`, Segoe UI) built for long SOC sessions |
| 🔌 **Dynamic Plugin Discovery** | Queries `vol -h` on launch — auto-discovers every installed plugin including community ones |
| ⚙️ **Smart Context-Awareness** | Auto-detects OS from dump extension; adapts UI and plugin tree instantly |
| ⚡ **Non-Blocking Execution** | `QThread`-powered — queue multiple scans, browse results mid-scan, no freezes |
| 📝 **Automated Reporting** | Clean JSON + PDF reports with safe nested table rendering |
| 🔍 **Intelligent Search** | Real-time plugin filter — type `"net"` → instantly shows all network plugins |
| 🛡️ **AI Risk + Heuristics** | Heuristic scoring with per-PID AI probabilities; maps findings to MITRE ATT&CK |
| 🧭 **Capability Summary** | Adversary capability profiling: persistence · injection · evasion · C2 · exfiltration |
| 🧩 **Internal Triage Plugins** | Curated Windows & Linux plugins for instant, zero-config triage |

</div>

### 🧩 WinVolAuto Internal Plugin Reference

<table>
<tr>
<td width="50%">

**🪟 Windows Triage**

| Plugin | Purpose |
|---|---|
| `internal.win.cmdline` | Recover attacker-typed commands |
| `internal.win.pstree` | Visualize parent-child process hierarchy |
| `internal.win.kernel_scan` | Detect unauthorized kernel modifications |
| `internal.win.persistence_scan` | Identify persistence mechanisms |
| `internal.win.text_scan` | Locate & preview text files from RAM |

</td>
<td width="50%">

**🐧 Linux Triage**

| Plugin | Purpose |
|---|---|
| `internal.linux.pslist` | Flag `/tmp` & `/dev/shm` execution + root shells |
| `internal.linux.bash` | Summarize risky bash history (curl/wget/nc/base64) |
| `internal.linux.check_syscall` | Count hooked syscalls → rootkit detection |
| `internal.linux.elfs` | Flag ELF modules from transient folders |

</td>
</tr>
</table>

---

## 🎯 What Can It Do?

```mermaid
%%{init: {'theme': 'dark'}}%%
mindmap
  root((WinVolAuto))
    Malware Hunting
      Hidden Process Detection
        DKOM Attack Discovery
        pslist vs psscan Cross-Check
      Code Injection Analysis
        malfind RWX Pages
        Shellcode Identification
      Network Forensics
        Active and Closed Connections
        C2 Traffic Tracing
    Rootkit Detection
      Kernel Hook Analysis
      Driver Integrity Verification
      Unsigned Module Detection
    Incident Response
      Command History Recovery
      Binary Extraction from RAM
      Deleted File Recovery
      Linux Triage Automation
    AI-Powered Analysis
      Per-PID Risk Probability
      MITRE ATT&CK Mapping
      Adversary Capability Profiling
```

### Real-World Use Cases

> **🦠 Malware Hunting** — Use `windows.pslist` + `windows.psscan` cross-comparison to expose DKOM-hidden processes. Run `windows.malfind` to find RWX memory pages with injected shellcode. Enable AI Risk Probability to rank all PIDs by threat score — investigate highest-risk processes first.

> **🔩 Rootkit Detection** — Analyze kernel modules and loaded drivers to find unauthorized system modifications. Spot unsigned or suspicious kernel extensions that standard AV misses.

> **🚨 Incident Response** — Extract full console command history to reconstruct attacker TTPs. Dump `.exe`/`.dll` binaries directly from RAM for offline reverse engineering, even after disk deletion. Use `internal.win.text_scan` to preview text artifacts still resident in memory.

> **🐧 Linux Forensics** — Instantly triage Linux memory for `/tmp` execution, risky bash history, hooked syscalls, and suspicious ELF modules loaded from transient directories.

---

## 🏗️ Architecture & Workings

<div align="center">

```mermaid
%%{init: {'theme': 'dark'}}%%
flowchart LR
    subgraph Init["🚀 Initialization"]
        PY[Python Env]
        VH["vol --help\nJSON Parse"]
        GT[GUI Tree\nBuild]
    end

    subgraph Config["⚙️ Configuration"]
        PS[Plugin Select]
        PCW[PluginConfigWidget\nDynamic Args]
        CB[Checkboxes and\nText Inputs]
    end

    subgraph Exec["⚡ Execution"]
        VE[VolatilityEngine]
        SC["Sanitized Command\nvol -f dump -r json plugin"]
        OS[OS Process\nSpawn]
    end

    subgraph Parse["📊 Result Parsing"]
        JP[JSON Parser]
        RV[ResultsView\nSortable Tables]
        PT[ProcessTree\nHierarchy Viz]
        RA[Risk Analyzer\nAI + MITRE]
        CA[Capability\nAnalyzer]
    end

    PY --> VH --> GT
    GT --> PS --> PCW --> CB
    CB --> VE --> SC --> OS
    OS -->|stdout/stderr| JP
    JP --> RV & PT & RA & CA

    style PY fill:#1e293b,stroke:#4D6AF5,color:#fff
    style VH fill:#1e293b,stroke:#00D4AA,color:#fff
    style GT fill:#1e293b,stroke:#41CD52,color:#fff
    style PS fill:#1e293b,stroke:#7B2FBE,color:#fff
    style PCW fill:#1e293b,stroke:#7B2FBE,color:#fff
    style CB fill:#1e293b,stroke:#7B2FBE,color:#fff
    style VE fill:#1e293b,stroke:#EE4C2C,color:#fff
    style SC fill:#1e293b,stroke:#FF6B6B,color:#fff
    style OS fill:#1e293b,stroke:#FF6B6B,color:#fff
    style JP fill:#1e293b,stroke:#F59E0B,color:#fff
    style RV fill:#1e293b,stroke:#41CD52,color:#fff
    style PT fill:#1e293b,stroke:#41CD52,color:#fff
    style RA fill:#1e293b,stroke:#EE4C2C,color:#fff
    style CA fill:#1e293b,stroke:#EE4C2C,color:#fff
```

</div>

### The 4-Phase Pipeline

<table>
<tr>
<td width="25%" align="center"><strong>Phase 1</strong><br/>🚀 Init</td>
<td width="75%">App launches, locates Python env, executes <code>vol.exe --help</code> in a hidden process, parses all plugin JSON descriptors, and dynamically builds the GUI tree.</td>
</tr>
<tr>
<td align="center"><strong>Phase 2</strong><br/>⚙️ Config</td>
<td>When you select a plugin (e.g., <code>windows.pslist</code>), <strong>PluginConfigWidget</strong> reads its required arguments and dynamically generates checkboxes for boolean flags and text fields for string arguments — with hover tooltips from Volatility's own help text.</td>
</tr>
<tr>
<td align="center"><strong>Phase 3</strong><br/>⚡ Execute</td>
<td><strong>VolatilityEngine</strong> constructs a sanitized, safe command: <code>vol.exe -f &lt;dump&gt; -r json &lt;plugin&gt; &lt;args&gt;</code>, spawns it as a separate OS process, and captures stdout/stderr in real-time streams. The UI stays fully responsive via <code>QThread</code>.</td>
</tr>
<tr>
<td align="center"><strong>Phase 4</strong><br/>📊 Parse</td>
<td>Raw JSON → <strong>ResultsView</strong> (sortable tables) + <strong>ProcessTree</strong> (parent-child hierarchy) + <strong>Risk Analyzer</strong> (AI probabilities, MITRE mapping) + <strong>Capability Analyzer</strong> (persistence · injection · evasion · C2 · exfiltration).</td>
</tr>
</table>

---

## 🛠️ Installation & Setup

### Prerequisites

| # | Requirement | Notes |
|---|---|---|
| 1 | **Python 3.10+** | Modern language features required |
| 2 | **Volatility 3** | Core forensics engine |
| 3 | **Visual C++ Redistributable** | Windows only — prevents DLL load failures |

### Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/SKYLINE217/WinVolAuto-Memory-Forensics-Suite.git
cd WinVolAuto-Memory-Forensics-Suite

# 2. Install Volatility 3 (the forensics engine)
pip install volatility3

# 3. Install Python dependencies (PyQt6 + helpers)
pip install -r requirements.txt

# 4. Launch WinVolAuto
python main.py
```

> [!TIP]
> On first launch, WinVolAuto will auto-query your Volatility installation to build the plugin tree. This takes a few seconds — subsequent launches are instant.

---

## 📊 The Dashboard: A Detailed Tour

<div align="center">

```mermaid
%%{init: {'theme': 'dark'}}%%
graph TB
    subgraph Header["🖥️ Header Bar"]
        HB["WinVolAuto Professional — Status and Actions"]
    end
    subgraph Top["📂 File Selection Zone"]
        FI["File Path Input — .raw · .mem · .dmp · .vmem · .elf · .core"]
        BR["Browse Button — Smart Filter + Auto OS Detection"]
    end
    subgraph Left["🌳 Plugin Navigator"]
        TV["Tree View — windows · linux · mac · banners · WinVolAuto"]
        SF["Real-Time Search Filter"]
    end
    subgraph Right["⚙️ Config Panel"]
        FC["Flag Checkboxes"]
        AI_["Argument Inputs"]
        GL["Global Toggles — VirusTotal and AI Risk Probability"]
    end
    subgraph Bottom["💻 Live Console Output"]
        LC["Scrolling Terminal — Raw command + real-time stderr/stdout"]
    end

    Header --> Top
    Top --> Left
    Top --> Right
    Left --> Bottom
    Right --> Bottom

    style Header fill:#1e293b,stroke:#7B2FBE,color:#fff
    style Top fill:#1e293b,stroke:#4D6AF5,color:#fff
    style Left fill:#1e293b,stroke:#00D4AA,color:#fff
    style Right fill:#1e293b,stroke:#41CD52,color:#fff
    style Bottom fill:#1e293b,stroke:#FF6B6B,color:#fff
```

</div>

| Zone | What It Does |
|:---:|:---|
| 🔝 **Header** | Displays app title and real-time status bar (Scanning… / Ready / Error) |
| 📂 **File Zone** | Browse button with smart format filter; auto-detects Windows vs Linux context on selection |
| 🌳 **Plugin Tree** | Hierarchical navigator: `windows` · `linux` · `mac` · `banners` · WinVolAuto internal plugins |
| 🔍 **Search Filter** | Type `"net"` → instantly isolates `windows.netscan`, `linux.netstat`, etc. |
| ⚙️ **Config Panel** | Dynamic per-plugin argument UI with Volatility-sourced tooltips; VT + AI toggles |
| 💻 **Live Console** | Real-time scrolling terminal — shows exact command run + raw error output for debugging |

---

## 🐧 Supported OS & File Types

<div align="center">

| OS | File Extensions | Notes |
|:---:|:---|:---|
| 🪟 **Windows** | `.raw` `.mem` `.dmp` `.vmem` | Full plugin support — `pslist` · `cmdline` · `filescan` · `hivescan` + more |
| 🐧 **Linux** | `.elf` `.core` | Requires kernel-matched symbol table in `volatility3/symbols/` |
| 🍎 **macOS** | `.mem` `.raw` | Standard plugins via `mac` category |

</div>

> [!IMPORTANT]
> **Linux Symbol Tables** — Linux memory forensics is kernel-version specific. You must generate a symbol file for the exact kernel of the target machine using `dwarf2json`, then place the resulting JSON in your `volatility3/symbols/` directory.

---

## ❓ Troubleshooting

<details>
<summary><strong>🔴 "Unsatisfied requirement: symbol_table_name" (Linux)</strong></summary>

**Problem:** Scanning a Linux `.elf` file without a matching kernel symbol table.  
**Solution:** Run `dwarf2json` on the original Linux machine to generate kernel JSON symbols. Place the output in `volatility3/symbols/`. The filename must match the kernel version string.

</details>

<details>
<summary><strong>🔴 "vol.exe not found"</strong></summary>

**Problem:** WinVolAuto cannot locate the Volatility executable in your PATH.  
**Solution:** Run `pip install volatility3`. The app searches your Python `Scripts` directory automatically.

</details>

<details>
<summary><strong>🔴 "DLL Load Failed" (Windows)</strong></summary>

**Problem:** Missing Visual C++ Redistributables.  
**Solution:** Download and install the latest **Microsoft Visual C++ Redistributable** from the official Microsoft website.

</details>

<details>
<summary><strong>🔴 "PDF cell too large"</strong></summary>

**Problem:** Very large result sets caused cell overflow in generated PDF reports.  
**Solution:** This is handled automatically — reports now render nested tables and truncated previews for large lists and dictionaries, preventing overflow.

</details>

---

## ⚖️ Legal Disclaimer

> [!WARNING]
> **WinVolAuto** is a specialized tool intended **only** for authorized security research, digital forensics, and incident response activities.
>
> - **Authorization**: You must have **explicit written permission** to capture and analyze the memory of any system you target.
> - **Liability**: The creators of WinVolAuto are **not liable** for any misuse of this software or for any damage caused by its operation.
> - **Compliance**: Users are solely responsible for complying with all applicable local, state, and federal laws regarding data privacy and computer security.

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0D1117,50:7B2FBE,100:00D4AA&height=120&section=footer" width="100%"/>

**Developed for the Cyber Security Community** 🛡️

[![GitHub](https://img.shields.io/badge/GitHub-SKYLINE217-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/SKYLINE217)
![Visitors](https://visitor-badge.laobi.icu/badge?page_id=SKYLINE217.WinVolAuto-Memory-Forensics-Suite)

*Built with ❤️ for digital forensics investigators everywhere.*

</div>
