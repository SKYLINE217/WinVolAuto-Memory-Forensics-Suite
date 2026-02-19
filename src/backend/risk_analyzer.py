import re
import math

class RiskAnalyzer:
    def __init__(self):
        self.scores = {
            "hidden_process": 30,
            "unsigned_dll": 25,
            "suspicious_network": 20,
            "code_injection": 40,
            "suspicious_parent": 35,
            "suspicious_path": 15,
            "encoded_command": 25,
            "masquerading": 30,
            "unusual_service": 20
        }
        
        # Knowledge Base for Heuristics
        self.suspicious_ports = {4444, 1337, 6667, 31337, 12345}
        self.risky_processes = {'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe'}
        
        # Expected Parent-Child relationships
        self.expected_parents = {
            'svchost.exe': {'services.exe'},
            'services.exe': {'wininit.exe'},
            'lsass.exe': {'wininit.exe'},
            'lsm.exe': {'wininit.exe'},
            'winlogon.exe': {'smss.exe'},
            'explorer.exe': {'userinit.exe', 'winlogon.exe'}
        }
        
        # Suspicious parent spawns (Parent -> Child)
        self.suspicious_spawns = {
            'winword.exe': {'cmd.exe', 'powershell.exe'},
            'excel.exe': {'cmd.exe', 'powershell.exe'},
            'outlook.exe': {'cmd.exe', 'powershell.exe'},
            'chrome.exe': {'powershell.exe', 'cmd.exe'},
            'iexplore.exe': {'powershell.exe', 'cmd.exe'}
        }
        self.ai_enabled = True
        self.ai_weights = {
            "bias": -2.5,
            "injections": 0.9,
            "hidden": 0.7,
            "susp_ports": 0.3,
            "risky_conns": 0.4,
            "hier_anoms": 0.5,
            "encoded": 0.6,
            "temp_exec": 0.4
        }

    def analyze(self, results):
        total_risk = 0
        details = []
        suspicious_pids = set()
        features = {
            "injections": 0,
            "hidden": 0,
            "susp_ports": 0,
            "risky_conns": 0,
            "hier_anoms": 0,
            "encoded": 0,
            "temp_exec": 0
        }
        
        def get_pid(row):
            return str(row.get("PID", row.get("Pid", "")))

        if "windows.malfind" in results:
            malfind_data = results["windows.malfind"]
            if isinstance(malfind_data, list):
                injections = 0
                for row in malfind_data:
                    if isinstance(row, dict):
                        injections += 1
                        pid = get_pid(row)
                        suspicious_pids.add(pid)
                
                if injections > 0:
                    score = self.scores["code_injection"] * min(injections, 5) # Cap multiplier
                    total_risk += score
                    details.append(f"Detected {injections} potential code injection sites (Risk: +{score})")
                features["injections"] = injections

        if "windows.pslist" in results and "windows.psscan" in results:
            pslist_pids = {get_pid(row) for row in results["windows.pslist"] if isinstance(row, dict)}
            psscan_pids = {get_pid(row) for row in results["windows.psscan"] if isinstance(row, dict)}
            
            pslist_pids.discard("")
            psscan_pids.discard("")
            
            hidden = psscan_pids - pslist_pids
            if hidden:
                score = self.scores["hidden_process"] * len(hidden)
                total_risk += score
                details.append(f"Detected {len(hidden)} hidden processes (DKOM) (PIDs: {', '.join(hidden)}) (Risk: +{score})")
                suspicious_pids.update(hidden)
            features["hidden"] = len(hidden)

        if "windows.netscan" in results:
            netscan = results["windows.netscan"]
            net_score = 0
            suspicious_conns = []
            
            for row in netscan:
                if not isinstance(row, dict): continue
                
                local_port = row.get("LocalPort")
                remote_port = row.get("RemotePort")
                owner = str(row.get("Owner", "")).lower()
                state = row.get("State", "")
                
                try:
                    if remote_port and int(remote_port) in self.suspicious_ports:
                        net_score += 20
                        suspicious_conns.append(f"Connection to suspicious port {remote_port} by {owner}")
                        features["susp_ports"] += 1
                    
                    if local_port and int(local_port) in self.suspicious_ports:
                        net_score += 20
                        suspicious_conns.append(f"Listening on suspicious port {local_port} by {owner}")
                        features["susp_ports"] += 1
                except (ValueError, TypeError):
                    pass
                
                if owner in self.risky_processes and state == "ESTABLISHED":
                    net_score += 10
                    suspicious_conns.append(f"Risky process {owner} has active network connection")
                    features["risky_conns"] += 1

            if net_score > 0:
                total_risk += net_score
                details.append(f"Network Anomalies Detected (Risk: +{net_score}): " + "; ".join(suspicious_conns[:3]))

        if "windows.pslist" in results:
            pslist = results["windows.pslist"]
            proc_map = {get_pid(row): row for row in pslist if isinstance(row, dict)}
            
            hierarchy_score = 0
            anomaly_details = []
            
            for row in pslist:
                if not isinstance(row, dict): continue
                
                pid = get_pid(row)
                ppid = str(row.get("PPID", row.get("Ppid", "")))
                name = str(row.get("ImageFileName", row.get("Name", ""))).lower()
                
                if name in self.expected_parents:
                    parent_row = proc_map.get(ppid)
                    parent_name = str(parent_row.get("ImageFileName", parent_row.get("Name", ""))).lower() if parent_row else "unknown"
                    
                    if parent_row and parent_name not in self.expected_parents[name]:
                        hierarchy_score += 25
                        anomaly_details.append(f"Process {name} (PID {pid}) spawned by unexpected parent {parent_name} (PID {ppid})")
                        suspicious_pids.add(pid)
                        features["hier_anoms"] += 1

                parent_row = proc_map.get(ppid)
                if parent_row:
                    parent_name = str(parent_row.get("ImageFileName", parent_row.get("Name", ""))).lower()
                    if parent_name in self.suspicious_spawns and name in self.suspicious_spawns[parent_name]:
                        hierarchy_score += 35
                        anomaly_details.append(f"Suspicious spawn: {parent_name} created {name} (PID {pid})")
                        suspicious_pids.add(pid)
                        features["hier_anoms"] += 1

                if name in ['svhost.exe', 'svchost.exe.exe', 'cvchost.exe', 'explore.exe']:
                    hierarchy_score += 30
                    anomaly_details.append(f"Potential masquerading detected: {name} (PID {pid})")
                    suspicious_pids.add(pid)
                    features["hier_anoms"] += 1

            if hierarchy_score > 0:
                total_risk += hierarchy_score
                details.append(f"Process Hierarchy Anomalies (Risk: +{hierarchy_score}): " + "; ".join(anomaly_details[:3]))

        if "windows.cmdline" in results:
            cmdline_data = results["windows.cmdline"]
            cmd_score = 0
            cmd_details = []
            
            for row in cmdline_data:
                if not isinstance(row, dict): continue
                
                args = str(row.get("Args", "")).lower()
                pid = get_pid(row)
                
                if "powershell" in args and ("-enc" in args or "-encodedcommand" in args):
                    cmd_score += 25
                    cmd_details.append(f"Encoded PowerShell command detected (PID {pid})")
                    suspicious_pids.add(pid)
                    features["encoded"] += 1
                
                if "\\appdata\\" in args or "\\temp\\" in args:
                    if ".exe" in args:
                        cmd_score += 15
                        cmd_details.append(f"Process running from Temp/AppData (PID {pid})")
                        suspicious_pids.add(pid)
                        features["temp_exec"] += 1

            if cmd_score > 0:
                total_risk += cmd_score
                details.append(f"Suspicious Command Lines (Risk: +{cmd_score}): " + "; ".join(cmd_details[:3]))

        prob = None
        if self.ai_enabled:
            z = (
                self.ai_weights["bias"]
                + self.ai_weights["injections"] * features["injections"]
                + self.ai_weights["hidden"] * features["hidden"]
                + self.ai_weights["susp_ports"] * features["susp_ports"]
                + self.ai_weights["risky_conns"] * features["risky_conns"]
                + self.ai_weights["hier_anoms"] * features["hier_anoms"]
                + self.ai_weights["encoded"] * features["encoded"]
                + self.ai_weights["temp_exec"] * features["temp_exec"]
            )
            prob = 1.0 / (1.0 + math.exp(-z))
        level = "Critical" if total_risk > 100 else "High" if total_risk > 60 else "Medium" if total_risk > 30 else "Low"
        if prob is not None:
            if prob >= 0.85:
                level = "Critical"
            elif prob >= 0.6 and level in ["Low", "Medium"]:
                level = "High"
        # Per-PID probabilities
        pid_features = {}
        def bump_pid(pid, key, amount=1):
            if not pid:
                return
            d = pid_features.setdefault(pid, {"injections":0, "hidden":0, "susp_ports":0, "risky_conns":0, "hier_anoms":0, "encoded":0, "temp_exec":0})
            d[key] += amount
        # Build per-PID features from available sources
        if "windows.malfind" in results:
            for row in results["windows.malfind"]:
                if isinstance(row, dict):
                    bump_pid(get_pid(row), "injections", 1)
        if "windows.pslist" in results and "windows.psscan" in results:
            pslist_pids = {get_pid(row) for row in results["windows.pslist"] if isinstance(row, dict)}
            psscan_pids = {get_pid(row) for row in results["windows.psscan"] if isinstance(row, dict)}
            pslist_pids.discard(""); psscan_pids.discard("")
            hidden = psscan_pids - pslist_pids
            for h in hidden:
                bump_pid(h, "hidden", 1)
        if "windows.netscan" in results:
            for row in results["windows.netscan"]:
                if not isinstance(row, dict): continue
                owner = str(row.get("Owner", "")).lower()
                pid = get_pid(row)
                try:
                    lp = int(row.get("LocalPort")) if row.get("LocalPort") else None
                    rp = int(row.get("RemotePort")) if row.get("RemotePort") else None
                except (TypeError, ValueError):
                    lp = rp = None
                if rp and rp in self.suspicious_ports:
                    bump_pid(pid, "susp_ports", 1)
                if lp and lp in self.suspicious_ports:
                    bump_pid(pid, "susp_ports", 1)
                if owner in self.risky_processes and row.get("State") == "ESTABLISHED":
                    bump_pid(pid, "risky_conns", 1)
        if "windows.pslist" in results:
            pslist = results["windows.pslist"]
            proc_map = {get_pid(row): row for row in pslist if isinstance(row, dict)}
            for row in pslist:
                if not isinstance(row, dict): continue
                pid = get_pid(row); ppid = str(row.get("PPID", row.get("Ppid", "")))
                name = str(row.get("ImageFileName", row.get("Name", ""))).lower()
                parent_row = proc_map.get(ppid)
                parent_name = str(parent_row.get("ImageFileName", parent_row.get("Name", ""))).lower() if parent_row else "unknown"
                if name in self.expected_parents and parent_row and parent_name not in self.expected_parents[name]:
                    bump_pid(pid, "hier_anoms", 1)
                if parent_row and parent_name in self.suspicious_spawns and name in self.suspicious_spawns[parent_name]:
                    bump_pid(pid, "hier_anoms", 1)
                if name in ['svhost.exe', 'svchost.exe.exe', 'cvchost.exe', 'explore.exe']:
                    bump_pid(pid, "hier_anoms", 1)
        if "windows.cmdline" in results:
            for row in results["windows.cmdline"]:
                if not isinstance(row, dict): continue
                pid = get_pid(row); args = str(row.get("Args", "")).lower()
                if "powershell" in args and ("-enc" in args or "-encodedcommand" in args):
                    bump_pid(pid, "encoded", 1)
                if ("\\appdata\\" in args or "\\temp\\" in args) and ".exe" in args:
                    bump_pid(pid, "temp_exec", 1)
        pid_probabilities = {}
        if self.ai_enabled:
            for pid, f in pid_features.items():
                z_pid = (
                    self.ai_weights["bias"]
                    + self.ai_weights["injections"] * f["injections"]
                    + self.ai_weights["hidden"] * f["hidden"]
                    + self.ai_weights["susp_ports"] * f["susp_ports"]
                    + self.ai_weights["risky_conns"] * f["risky_conns"]
                    + self.ai_weights["hier_anoms"] * f["hier_anoms"]
                    + self.ai_weights["encoded"] * f["encoded"]
                    + self.ai_weights["temp_exec"] * f["temp_exec"]
                )
                pid_probabilities[pid] = 1.0 / (1.0 + math.exp(-z_pid))
        # MITRE mapping
        mitre_map = {
            "code_injection": ["T1055"],
            "hidden_process": ["T1564"],
            "suspicious_network": ["T1071", "T1041"],
            "suspicious_parent": ["T1059", "T1204"],
            "masquerading": ["T1036"],
            "encoded_command": ["T1059.001"],
            "suspicious_path": ["T1036", "T1105"]
        }
        mitre_techniques = set()
        if features["injections"] > 0: mitre_techniques.update(mitre_map["code_injection"])
        if features["hidden"] > 0: mitre_techniques.update(mitre_map["hidden_process"])
        if features["susp_ports"] > 0 or features["risky_conns"] > 0: mitre_techniques.update(mitre_map["suspicious_network"])
        if features["hier_anoms"] > 0: mitre_techniques.update(mitre_map["suspicious_parent"])
        if features["encoded"] > 0: mitre_techniques.update(mitre_map["encoded_command"])
        if features["temp_exec"] > 0: mitre_techniques.update(mitre_map["suspicious_path"])
        return {
            "total_score": total_risk,
            "details": details,
            "suspicious_pids": list(suspicious_pids),
            "level": level,
            "probability": prob,
            "ai_features": features,
            "pid_probabilities": pid_probabilities,
            "mitre_techniques": sorted(mitre_techniques)
        }
