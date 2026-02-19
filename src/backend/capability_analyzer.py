def _exists(val):
    return val is not None and val != ""

class CapabilityAnalyzer:
    def __init__(self):
        self.cap_defs = [
            {
                "name": "Command and Control",
                "key": "c2",
                "desc": "External communications or listening on suspicious ports indicative of C2.",
            },
            {
                "name": "Persistence",
                "key": "persistence",
                "desc": "Mechanisms to survive reboot or maintain foothold.",
            },
            {
                "name": "Code Injection",
                "key": "injection",
                "desc": "Injected or hidden code in process memory.",
            },
            {
                "name": "Masquerading/Evasion",
                "key": "evasion",
                "desc": "Deceptive names or execution from suspicious paths.",
            },
            {
                "name": "Execution",
                "key": "execution",
                "desc": "Use of interpreters, scripts, or encoded commands for execution.",
            },
            {
                "name": "Stealth",
                "key": "stealth",
                "desc": "Hidden processes or hierarchy anomalies to avoid detection.",
            },
            {
                "name": "Exfiltration Potential",
                "key": "exfil",
                "desc": "Indications of data transfer outside the host.",
            },
        ]

    def analyze(self, results, risk_report):
        caps = []
        evid = {
            "c2": [],
            "persistence": [],
            "injection": [],
            "evasion": [],
            "execution": [],
            "stealth": [],
            "exfil": [],
        }
        netscan = results.get("windows.netscan", [])
        for row in netscan or []:
            if not isinstance(row, dict):
                continue
            owner = str(row.get("Owner", "")).lower()
            state = row.get("State", "")
            lp = row.get("LocalPort")
            rp = row.get("RemotePort")
            addr = row.get("ForeignAddr", row.get("RemoteAddr", ""))
            try:
                lp_i = int(lp) if _exists(lp) else None
                rp_i = int(rp) if _exists(rp) else None
            except Exception:
                lp_i = rp_i = None
            if rp_i and rp_i in {4444, 1337, 6667, 31337, 12345}:
                evid["c2"].append(f"{owner} connects to suspicious port {rp_i} {addr} {state}")
            if lp_i and lp_i in {4444, 1337, 6667, 31337, 12345}:
                evid["c2"].append(f"{owner} listens on suspicious port {lp_i}")
            if owner in {"powershell.exe","cmd.exe","mshta.exe"} and state == "ESTABLISHED":
                evid["exfil"].append(f"{owner} has established external connection {addr}")
        malfind = results.get("windows.malfind", [])
        for row in malfind or []:
            if isinstance(row, dict):
                pid = str(row.get("PID", row.get("Pid", "")))
                proc = str(row.get("Process", row.get("Name", "")))
                evid["injection"].append(f"Injected code suspected in {proc} PID {pid}")
        cmdline = results.get("windows.cmdline", [])
        for row in cmdline or []:
            if not isinstance(row, dict):
                continue
            args = str(row.get("Args", "")).lower()
            pid = str(row.get("PID", row.get("Pid", "")))
            if "powershell" in args and ("-enc" in args or "-encodedcommand" in args):
                evid["execution"].append(f"Encoded PowerShell command PID {pid}")
            if ("\\appdata\\" in args or "\\temp\\" in args) and ".exe" in args:
                evid["evasion"].append(f"Executable launched from Temp/AppData PID {pid}")
        pslist = results.get("windows.pslist", [])
        psscan = results.get("windows.psscan", [])
        pslist_pids = {str(row.get("PID", row.get("Pid", ""))) for row in pslist if isinstance(row, dict)}
        psscan_pids = {str(row.get("PID", row.get("Pid", ""))) for row in psscan if isinstance(row, dict)}
        pslist_pids.discard(""); psscan_pids.discard("")
        hidden = psscan_pids - pslist_pids
        for h in hidden:
            evid["stealth"].append(f"Hidden process detected PID {h}")
        svcscan = results.get("windows.svcscan", [])
        for row in svcscan or []:
            if not isinstance(row, dict):
                continue
            name = str(row.get("Name", ""))
            path = str(row.get("BinaryPath", row.get("ImagePath", ""))).lower()
            if "\\appdata\\" in path or "\\temp\\" in path:
                evid["persistence"].append(f"Service {name} points to {path}")
        callbacks = results.get("windows.callbacks", [])
        for row in callbacks or []:
            if not isinstance(row, dict):
                continue
            evid["persistence"].append("Kernel/user callbacks present")
        for cdef in self.cap_defs:
            key = cdef["key"]
            evidence = evid[key]
            score = 0
            if key == "c2":
                score = len(evidence) * 20
            elif key == "injection":
                score = len(evidence) * 40
            elif key == "stealth":
                score = len(evidence) * 30
            elif key == "execution":
                score = len(evidence) * 25
            elif key == "evasion":
                score = len(evidence) * 20
            elif key == "persistence":
                score = len(evidence) * 20
            elif key == "exfil":
                score = len(evidence) * 20
            if evidence:
                caps.append({
                    "name": cdef["name"],
                    "desc": cdef["desc"],
                    "score": score,
                    "evidence": evidence[:10]
                })
        caps.sort(key=lambda x: x["score"], reverse=True)
        return caps
