import subprocess
import json
import os
import threading
from PyQt6.QtCore import QObject, pyqtSignal
from src.backend.plugin_discovery import PluginDiscovery

class VolatilityWorker(QObject):
    finished = pyqtSignal(dict)
    progress = pyqtSignal(str)
    error = pyqtSignal(dict)

    def __init__(self, dump_path, plugin, profile=None, additional_args=None):
        super().__init__()
        self.dump_path = dump_path
        self.plugin = plugin
        self.profile = profile # Not always needed for Vol3 as it auto-detects, but good to have
        self.additional_args = additional_args or []
        self.process = None

    def run(self):
        # Find vol.exe
        pd = PluginDiscovery()
        if not pd.vol_path:
             self.error.emit({"plugin": self.plugin, "message": "vol.exe not found"})
             return

        # Construct command: vol.exe -f <dump> <plugin> --renderer json
        # We use JSON renderer to parse output easily
        
        cmd = [
            pd.vol_path,
            "-f", self.dump_path,
            "-r", "json", # Request JSON output
            self.plugin
        ]
        
        if self.additional_args:
            cmd.extend(self.additional_args)
            
        self.progress.emit(f"Starting {self.plugin}...")
        
        try:
            # Using subprocess.run for simplicity, but Popen is better for real-time output
            # For JSON, we usually wait for the full output
            
            # CREATE_NO_WINDOW = 0x08000000
            creationflags = 0x08000000 if os.name == 'nt' else 0
            
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=creationflags
            )
            
            stdout, stderr = self.process.communicate()
            
            if self.process.returncode != 0:
                self.error.emit({"plugin": self.plugin, "message": f"Error running {self.plugin}: {stderr}"})
                return

            try:
                data = json.loads(stdout)
                self.finished.emit({"plugin": self.plugin, "data": data})
                
            except json.JSONDecodeError:
                # Fallback: attempt line-wise JSON parsing and accumulate
                parsed = []
                for line in stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("{") or line.startswith("["):
                        try:
                            obj = json.loads(line)
                            if isinstance(obj, list):
                                parsed.extend(obj)
                            else:
                                parsed.append(obj)
                        except Exception:
                            continue
                if parsed:
                    self.finished.emit({"plugin": self.plugin, "data": parsed})
                else:
                    self.error.emit({"plugin": self.plugin, "message": f"Failed to parse JSON output from {self.plugin}. Raw: {stdout[:200]}..."})

        except Exception as e:
            self.error.emit({"plugin": self.plugin, "message": str(e)})

    def cancel(self):
        if self.process:
            self.process.terminate()

class VolatilityEngine:
    def __init__(self):
        from src.backend.internal_plugins import InternalPlugins
        self.internal = InternalPlugins()

    def run_plugin(self, dump_path, plugin, callback, error_callback, additional_args=None):
        if plugin.startswith("internal."):
            self.internal.run(dump_path, plugin, callback, error_callback)
            return None
        worker = VolatilityWorker(dump_path, plugin, additional_args=additional_args)
        worker.finished.connect(callback)
        worker.error.connect(error_callback)
        thread = threading.Thread(target=worker.run)
        thread.daemon = True
        thread.start()
        return worker
