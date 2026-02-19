# 🛡️ WinVolAuto - Professional Memory Forensics Suite

**WinVolAuto** is a powerful, user-friendly desktop application designed to make memory forensics simple, accessible, and highly efficient. Built on top of the industry-standard **Volatility 3** framework, it provides a sleek, modern interface for analyzing memory dumps from Windows, Linux, and Mac systems.

Whether you are a seasoned malware analyst, a security researcher, or a student learning digital forensics, WinVolAuto handles the complex command-line operations for you, allowing you to focus on the investigation results.

---

## 📑 Table of Contents
1. [Key Features](#-key-features)
2. [What Can It Do?](#-what-can-it-do)
3. [Architecture & Workings](#-architecture--workings)
4. [Installation & Setup](#-installation--setup)
5. [The Dashboard: A Detailed Tour](#-the-dashboard-a-detailed-tour)
6. [Supported OS & File Types](#-supported-os--file-types)
7. [Troubleshooting](#-troubleshooting)
8. [Legal Disclaimer](#-legal-disclaimer)

---

## 🚀 Key Features

*   **🖥️ Professional Dark Mode UI**: A carefully crafted dark-themed interface (`#1e1e1e` background, Segoe UI font) designed for long analysis sessions in low-light SOC environments.
*   **🔌 Dynamic Plugin Discovery Engine**: Unlike static tools, WinVolAuto queries your local Volatility installation (`vol -h`) to discover *every* available plugin dynamically. If you add a new community plugin to Volatility, WinVolAuto sees it automatically.
*   **⚙️ Smart Context-Aware Configuration**:
    *   **Auto-Detection**: Recognizes if you load a Windows `.mem` file or a Linux `.elf` core dump.
    *   **Adaptive UI**: Automatically expands the relevant plugin category (e.g., "Linux" folder opens for `.elf` files) and filters options.
*   **⚡ Non-Blocking Asynchronous Execution**: Built on `QThread` technology, scans run in the background. You can queue up multiple tasks or browse results while a heavy scan (like `windows.filescan`) runs without freezing the app.
*   **📝 Automated Reporting**: Generates clean JSON and PDF reports with safe table rendering.
*   **🔍 Intelligent Search**: Includes a real-time search filter to instantly find plugins among hundreds of options (e.g., typing "net" reveals `windows.netscan`, `linux.netstat`, etc.).
*   **🛡️ Risk Analysis & Heuristics + AI**: Heuristic scoring with AI Risk Probability; ranks suspicious PIDs and maps MITRE ATT&CK techniques.
*   **🧭 Malware Capabilities**: Summarizes likely adversary capabilities (persistence, injection, evasion, C2, exfiltration) with evidence strings.
*   **🧩 WinVolAuto Internal Plugins**: Curated Windows and Linux internal plugins for fast triage, including:
    *   Windows: `internal.win.cmdline`, `internal.win.pstree`, `internal.win.kernel_scan`, `internal.win.persistence_scan`, `internal.win.text_scan`
    *   Linux: `internal.linux.pslist`, `internal.linux.bash`, `internal.linux.check_syscall`, `internal.linux.elfs`
*   **🗂️ Curated Plugin Descriptions**: Clear, human-readable descriptions shown in the UI and included in reports so users understand each plugin before use.

---

## 🎯 What Can It Do?

WinVolAuto empowers you to perform deep-dive forensics without touching a command line. Here are some real-world use cases:

### 1. Malware Hunting
*   **Find Hidden Processes**: Use `windows.pslist` and `windows.psscan` to detect processes that are hiding from the Task Manager (DKOM attacks).
*   **Detect Code Injection**: Run `windows.malfind` to identify memory pages with suspicious permissions (Read/Write/Execute) that often indicate injected shellcode.
*   **Analyze Network Connections**: Use `windows.netscan` (or Linux equivalent) to see active connections, even those that were closed recently, helping you trace C2 (Command & Control) traffic.
*   **Rank Suspicious Processes**: Enable AI Risk Probability to get per‑PID probabilities and focus on the highest‑risk processes first.

### 2. Rootkit Detection
*   **Check System Hooks**: Analyze kernel modules and drivers to find unauthorized modifications.
*   **Verify Driver Integrity**: List loaded drivers to spot unsigned or suspicious kernel extensions.

### 3. Incident Response
*   **Recover Command History**: Extract console command history (`windows.cmdline`) to see what attackers typed.
*   **Dump Files from Memory**: Extract executable binaries (`.exe`, `.dll`) directly from RAM for reverse engineering, even if they were deleted from the disk.
*   **Read Text Files From RAM**: Use `internal.win.text_scan` to locate text-like files found in memory, preview their contents, and see folder distribution.
*   **Linux Triage**: Use internal Linux plugins to flag `/tmp` execution, risky bash history, syscall hooks, and unusual ELF modules.

---

## 🏗️ Architecture & Workings

Understanding how WinVolAuto works helps you trust its results.

### The Pipeline
1.  **Initialization**:
    *   The app launches and locates your Python environment.
    *   It executes `vol.exe --help` in a hidden process to parse the JSON output of all installed plugins and their specific arguments (flags, integers, strings).
    *   It builds the GUI tree dynamically based on this data.

2.  **Configuration Phase**:
    *   When you select a plugin (e.g., `windows.pslist`), the **PluginConfigWidget** reads the arguments required by that specific plugin.
    *   It dynamically generates checkboxes for boolean flags (e.g., `--physical`) and text boxes for string arguments (e.g., `--pid 1234`).

3.  **Execution Phase (The "Safe Mode")**:
    *   When you click "Start", the **VolatilityEngine** takes over.
    *   It constructs a safe, sanitized command: `vol.exe -f <dump_path> -r json <plugin> <args>`.
    *   This command is spawned in a separate OS process.
    *   Standard Output (stdout) and Standard Error (stderr) are captured in real-time streams.

4.  **Result Parsing**:
    *   Volatility returns raw JSON data.
    *   WinVolAuto parses this JSON into structured objects.
    *   The **ResultsView** renders this data into sortable, searchable tables.
    *   The **ProcessTree** visualizer specifically looks for parent-child relationships in process lists to draw a hierarchy.
    *   The **Risk Analyzer** extracts features (injections, hidden, network, hierarchy, encoded, temp execution) and computes AI probability and per‑PID probabilities. It also maps findings to MITRE ATT&CK techniques for context.
    *   The **Capability Analyzer** groups findings into attacker capabilities (persistence, injection, evasion, C2, exfiltration, stealth) with short evidence strings.

---

## 🛠️ Installation & Setup

### Prerequisites
1.  **Python 3.10+**: Required for modern features.
2.  **Volatility 3**: The core engine.
    ```bash
    pip install volatility3
    ```

### Installation Steps
1.  **Clone the Repository**:
    Download the source code to a folder of your choice.
2.  **Install Python Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
    *This installs `PyQt6` (for the GUI) and other helper libraries.*
3.  **Run the Application**:
    ```bash
    python main.py
    ```

---

## 📊 The Dashboard: A Detailed Tour

The interface is divided into logical zones to maximize workflow efficiency.

### 1. The Header & Status Area
*   **Top Bar**: Displays "WinVolAuto Professional".
*   **Status Bar (Bottom)**: Shows the current action (e.g., "Scanning...", "Ready") and error messages.

### 2. File Selection Zone (Top)
*   **File Input**: A text field showing the full path to your memory dump.
*   **Browse Button**: Opens a native OS file dialog.
    *   *Smart Filter*: Automatically looks for `.raw`, `.mem`, `.dmp`, `.vmem`, `.elf`, and `.core` files.
    *   *Auto-Context*: Selecting a file triggers the app to switch its internal mode (Windows vs. Linux) to save you clicks.

### 3. Plugin Navigator (Left Sidebar)
*   **Tree View**: Organized hierarchically.
    *   `windows`: Core Windows analysis (Registry, Processes, Files).
    *   `linux`: Linux kernel analysis (Bash history, Mounts, Process maps).
    *   `mac`: macOS specific plugins.
    *   `banners`: Identification plugins.
    *   `WinVolAuto (Sumit K.K.)`: Internal Windows triage plugins.
    *   `WinVolAuto Linux (Sumit K.K.)`: Internal Linux triage plugins.
*   **Search Filter**: A text box above the tree. Type "cmd" and it instantly hides everything except plugins related to command lines.

### 4. Dynamic Configuration Panel (Right Sidebar)
This is the "brain" of the setup. It changes every time you click a different plugin.
*   **Flag Checkboxes**: Toggle options like `--verbose` or `--physical`.
*   **Argument Inputs**: Text fields for specific parameters like Process IDs (PIDs) or virtual addresses.
*   **Tooltips**: Hover over any option to see the official help text from Volatility.
*   **Global Options**: Toggle VirusTotal integration and AI Risk Probability. AI enables probability in summaries and per‑PID ranking in the report and process tree.

### 5. Live Console Output (Bottom Center)
A scrolling black terminal window inside the app.
*   **Transparency**: Shows you exactly what command is being run.
*   **Debugging**: If a scan fails, this shows the raw error from Volatility (e.g., "Symbol table not found"), which is critical for troubleshooting.

---

## 🐧 Supported OS & File Types

### Windows
*   **File Types**: `.raw`, `.mem`, `.dmp` (Crash Dumps), `.vmem` (VMware).
*   **Support**: Full support for all standard plugins (`pslist`, `cmdline`, `filescan`, `hivescan`, etc.).

### Linux
*   **File Types**: `.elf` (Core Dumps), `.core`.
*   **Support**: Full support, **provided you have the correct Symbol Table**.
    *   *Note*: Linux memory forensics is kernel-specific. You must generate a symbol file for the specific kernel version of the target machine and place it in `volatility3/symbols`.
*   **Internal Triage**:
    *   `internal.linux.pslist`: Flags `/tmp` and `/dev/shm` execution paths and root shells.
    *   `internal.linux.bash`: Summarizes risky bash history commands (curl/wget/nc/base64/openssl enc/ssh).
    *   `internal.linux.check_syscall`: Counts hooked syscalls that indicate kernel rootkits.
    *   `internal.linux.elfs`: Flags ELF modules loaded from transient folders (e.g., `/tmp`, `/dev/shm`).

### macOS
*   **File Types**: `.mem`, `.raw`.
*   **Support**: Standard plugins supported via the `mac` category.

---

## ❓ Troubleshooting

### Common Issues

**1. "Unsatisfied requirement: symbol_table_name" (Linux)**
*   **Problem**: You are scanning a Linux `.elf` file but haven't provided the custom symbol table for that specific kernel.
*   **Solution**: Run the volatility symbol generator (dwarf2json) on the original Linux machine to create the JSON symbols, then add them to your Volatility symbols folder.

**2. "vol.exe not found"**
*   **Problem**: The app cannot locate the Volatility executable.
*   **Solution**: Ensure you have installed volatility3 (`pip install volatility3`). The app looks in your Python `Scripts` directory.

**3. "DLL Load Failed" (Windows)**
*   **Problem**: Missing Visual C++ Redistributables.
*   **Solution**: Install the latest "Microsoft Visual C++ Redistributable" package.

**4. "PDF cell too large"**
*   **Problem**: Huge blocks of text caused overflow in PDF cells.
*   **Solution**: Reports now render nested tables and truncated previews for large lists and dictionaries, preventing overflow.

---

## ⚖️ Legal Disclaimer

**WinVolAuto** is a specialized tool intended for **authorized security research, digital forensics, and incident response**.

*   **Authorization**: You must have explicit permission to capture and analyze the memory of any system you target.
*   **Liability**: The creators of WinVolAuto are not liable for any misuse of this software or for any damage caused by its operation.
*   **Compliance**: Users are responsible for complying with all applicable local, state, and federal laws regarding data privacy and computer security.

---

*Developed for the Cyber Security Community.*