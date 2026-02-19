
import subprocess
import os
import sys
import re
import json

class PluginDiscovery:
    def __init__(self):
        self.vol_path = self._find_vol_exe()
        self.plugins = {} # name -> description
        self.option_cache = {} # plugin_name -> options list
        self.curated_descriptions = {
            # Windows core
            "windows.pslist": "Enumerates active processes using kernel lists; baseline of running tasks.",
            "windows.psscan": "Carves memory for EPROCESS objects to find hidden/unlinked processes (DKOM).",
            "windows.pstree": "Shows parent-child process relationships to spot suspicious spawning chains.",
            "windows.cmdline": "Recovers process command-line arguments; flags encoded or obfuscated commands.",
            "windows.dlllist": "Lists loaded DLLs per process; helps identify injected or malicious libraries.",
            "windows.malfind": "Detects injected code via executable, private, and no-file-backed memory regions.",
            "windows.handles": "Lists open handles (files, registry, mutexes) for processes to reveal activity.",
            "windows.netscan": "Enumerates network endpoints and connections for C2 and exfil indicators.",
            "windows.callbacks": "Lists kernel callbacks; anomalies may indicate rootkits or monitoring hooks.",
            "windows.svcscan": "Enumerates Windows services and their binaries; suspicious paths indicate persistence.",
            "windows.filescan": "Scans memory for FILE_OBJECTs to find files touched by processes.",
            "windows.modules": "Lists loaded kernel modules; unsigned or unusual modules can be rootkits.",
            "windows.driverscan": "Carves memory for DRIVER_OBJECTs; detects drivers not on official lists.",
            "windows.registry.hivelist": "Lists registry hives present in memory for subsequent key inspection.",
            "windows.registry.printkey": "Displays registry key values; use with hivelist paths to inspect autoruns.",
            "windows.getservicesids": "Maps service names to SIDs; useful for privilege and identity checks.",
            "windows.getsids": "Lists SIDs for processes; detects impersonation or unusual identities.",
            "windows.logonsessions": "Shows user logon sessions; correlates with lateral movement or RDP use.",
            # Linux core
            "linux.pslist": "Enumerates running Linux processes from kernel structures.",
            "linux.bash": "Recovers bash history commands found in memory for activity reconstruction.",
            "linux.check_syscall": "Checks syscall table for hooks indicative of kernel rootkits.",
            "linux.elfs": "Lists ELF binaries loaded; detects unusual or injected modules.",
            # Mac core
            "mac.pslist": "Enumerates macOS processes; baseline of active tasks.",
            "mac.bash": "Recovers bash history lines from macOS memory.",
            "mac.check_syscall": "Checks macOS syscall table for potential hooks.",
            # Banners/other
            "banners.Banners": "Extracts version banners and strings that reveal OS and environment.",
        }
        # Internal curated descriptions
        self.curated_descriptions.update({
            "internal.win.cmdline": "WinVolAuto internal: summarizes suspicious command lines (encoded, web calls).",
            "internal.win.pstree": "WinVolAuto internal: highlights orphan processes and risky parent-child pairs.",
            "internal.win.kernel_scan": "WinVolAuto internal: summarises kernel callbacks that may indicate hooks.",
            "internal.win.persistence_scan": "WinVolAuto internal: flags services loading from Temp/AppData paths.",
            "internal.win.text_scan": "WinVolAuto internal: finds text-like files in RAM, previews content, summarizes folders.",
            "internal.linux.pslist": "WinVolAuto internal: triages Linux processes, flags /tmp exec and root shells.",
            "internal.linux.bash": "WinVolAuto internal: summarises risky bash history commands.",
            "internal.linux.check_syscall": "WinVolAuto internal: counts syscall hooks indicating rootkits.",
            "internal.linux.elfs": "WinVolAuto internal: flags ELF modules loaded from /tmp or /dev/shm.",
        })

    def _find_vol_exe(self):
        # Check common locations
        candidates = [
            os.path.join(sys.exec_prefix, "Scripts", "vol.exe"),
            os.path.join(os.path.dirname(sys.executable), "Scripts", "vol.exe"),
            # User site packages scripts
            os.path.join(os.getenv("APPDATA"), "Python", f"Python{sys.version_info.major}{sys.version_info.minor}", "Scripts", "vol.exe"),
        ]
        
        # Check PATH
        for path in os.environ["PATH"].split(os.pathsep):
            exe = os.path.join(path, "vol.exe")
            if os.path.exists(exe):
                return exe
                
        for cand in candidates:
            if os.path.exists(cand):
                return cand
                
        return None

    def get_all_plugins(self):
        """
        Returns a dict of {plugin_name: description}
        """
        if not self.vol_path:
            return {"error": "vol.exe not found"}

        try:
            # Run vol -h
            # We need to handle potential encoding issues
            result = subprocess.run([self.vol_path, "-h"], capture_output=True, text=True, encoding='utf-8', errors='ignore')
            if result.returncode != 0:
                return {"error": f"Failed to run vol -h: {result.stderr}"}
            
            output = result.stdout
            plugins = {}
            
            # Parse output
            # Look for "Plugins:" section
            in_plugins = False
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("Plugins:"):
                    in_plugins = True
                    continue
                
                if in_plugins:
                    if not line:
                        continue
                    # Plugin lines usually look like: "windows.pslist.PsList     Lists the processes..."
                    # Or just "windows.pslist     Lists..."
                    parts = line.split(maxsplit=1)
                    if len(parts) >= 1:
                        plugin_raw = parts[0]
                        
                        # Filter out non-plugin lines (headers, wrapped descriptions)
                        # Valid plugins usually have a dot (module.Class)
                        if "." not in plugin_raw:
                            continue

                        desc = parts[1] if len(parts) > 1 else ""
                        
                        # Clean up plugin name (sometimes it shows class name)
                        # We want the command name usable in CLI
                        # usually windows.pslist.PsList -> windows.pslist
                        if "." in plugin_raw:
                            parts_dot = plugin_raw.split(".")
                            # If the last part starts with uppercase (Class name convention)
                            if len(parts_dot) > 1 and parts_dot[-1] and parts_dot[-1][0].isupper():
                                plugin_clean = ".".join(parts_dot[:-1])
                                plugins[plugin_clean] = desc
                                continue
                        
                        plugins[plugin_raw] = desc
            
            self.plugins = plugins
            # Merge curated descriptions to improve coverage
            for name, desc in list(plugins.items()):
                cur = self.curated_descriptions.get(name)
                if cur and (not desc or len(desc) < 12):
                    plugins[name] = cur
            return plugins

        except Exception as e:
            return {"error": str(e)}

    def get_plugin_options(self, plugin_name):
        """
        Returns a list of options for a plugin.
        Each option is a dict: {name, type, help, required}
        """
        if not self.vol_path:
            return []
        if plugin_name in self.option_cache:
            return self.option_cache[plugin_name]

        try:
            # Run vol <plugin> -h
            cmd = [self.vol_path, plugin_name, "-h"]
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore')
            
            output = result.stdout
            options = []
            
            # Parse argparse help output
            # Options usually start with --
            # Example:
            #   --pid PID   Process ID to include
            
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("-"):
                    # Extract arg name
                    # handle "-p PID, --pid PID   Help text"
                    
                    # Regex to capture flags
                    # matches: -x, --long-name ARG   Help
                    match = re.match(r'((?:-[a-zA-Z0-9], )?(?:--[a-zA-Z0-9-]+))(.*)', line)
                    if match:
                        flags_part = match.group(1)
                        rest = match.group(2).strip()
                        
                        # Get the long flag name
                        long_flag = ""
                        for part in flags_part.split(','):
                            part = part.strip()
                            if part.startswith("--"):
                                long_flag = part
                        
                        if not long_flag:
                            # Maybe only short flag?
                            if flags_part.startswith("-"):
                                long_flag = flags_part # fallback
                        
                        # Extract argument type/metavar from 'rest' if present
                        # Standard argparse help formats:
                        #   --arg ARG           Help
                        #   --arg [ARG]         Help
                        #   --arg [ARG ...]     Help
                        
                        # Refined parsing logic
                        parts = re.split(r'\s{2,}', rest, maxsplit=1)
                        
                        arg_syntax = ""
                        help_text = rest
                        
                        if len(parts) > 1:
                            # We have a clear separation
                            # Check if the first part looks like syntax (short, brackets, CAPS)
                            # or if it's just the start of a long help sentence that happened to have a double space?
                            # Usually argparse aligns columns.
                            arg_syntax = parts[0].strip()
                            help_text = parts[1].strip()
                        else:
                            # One part. Is it syntax or help?
                            # If it starts with typical arg patterns: [ < or has uppercase words like PID, OFFSET
                            if re.match(r'^[\[<]', rest) or re.search(r'\b[A-Z]{2,}\b', rest):
                                arg_syntax = rest
                                help_text = ""
                            else:
                                arg_syntax = "" # It's just help
                                help_text = rest
                        
                        # Determine if it's a flag
                        is_flag = True
                        if arg_syntax:
                            # If syntax is present, it usually means it takes arguments
                            # UNLESS the syntax is just "show this help message" (unlikely here)
                            is_flag = False
                        
                        # Filter global args
                        if long_flag in ["--help", "--renderer", "--config", "--log", "--quiet", "--verbose", "--file", "--write-config", "--save-config", "--clear-cache"]:
                            continue

                        options.append({
                            "flag": long_flag,
                            "is_flag": is_flag,
                            "arg_syntax": arg_syntax,
                            "help": help_text
                        })
                        
            self.option_cache[plugin_name] = options
            return options

        except Exception as e:
            return []

if __name__ == "__main__":
    pd = PluginDiscovery()
    print(f"Vol path: {pd.vol_path}")
    plugins = pd.get_all_plugins()
    print(f"Found {len(plugins)} plugins")
    if "windows.pslist" in plugins: # key check might need adjustment based on output
        print("Options for windows.pslist:")
        print(pd.get_plugin_options("windows.pslist"))
    elif "windows.pslist.PsList" in plugins:
        print("Options for windows.pslist.PsList:")
        print(pd.get_plugin_options("windows.pslist.PsList"))
