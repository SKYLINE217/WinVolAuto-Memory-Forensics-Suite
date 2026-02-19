import threading
import os
import re
import tempfile
import shutil
from src.backend.volatility_engine import VolatilityWorker

class InternalPlugins:
    def run(self, dump_path, plugin_name, callback, error_callback):
        if plugin_name == "internal.win.cmdline":
            self._run_cmdline(dump_path, callback, error_callback)
        elif plugin_name == "internal.win.pstree":
            self._run_pstree(dump_path, callback, error_callback)
        elif plugin_name == "internal.win.kernel_scan":
            self._run_callbacks(dump_path, callback, error_callback)
        elif plugin_name == "internal.win.persistence_scan":
            self._run_svcscan(dump_path, callback, error_callback)
        elif plugin_name == "internal.win.text_scan":
            self._run_text_scan(dump_path, callback, error_callback)
        elif plugin_name == "internal.linux.pslist":
            self._run_linux_pslist(dump_path, callback, error_callback)
        elif plugin_name == "internal.linux.bash":
            self._run_linux_bash(dump_path, callback, error_callback)
        elif plugin_name == "internal.linux.check_syscall":
            self._run_linux_check_syscall(dump_path, callback, error_callback)
        elif plugin_name == "internal.linux.elfs":
            self._run_linux_elfs(dump_path, callback, error_callback)
        else:
            error_callback({"plugin": plugin_name, "message": "Unknown internal plugin"})

    def _run_single(self, dump_path, vol_plugin, internal_name, callback, error_callback):
        def on_ok(res):
            callback({"plugin": internal_name, "data": res["data"]})
        def on_err(err):
            error_callback({"plugin": internal_name, "message": err["message"]})
        worker = VolatilityWorker(dump_path, vol_plugin)
        worker.finished.connect(on_ok)
        worker.error.connect(on_err)
        t = threading.Thread(target=worker.run)
        t.daemon = True
        t.start()

    def _run_text_scan(self, dump_path, callback, error_callback):
        def on_filescan_ok(res):
            data = res["data"]
            text_exts = (".txt", ".log", ".cfg", ".ini", ".ps1", ".bat", ".cmd")
            candidates = []
            folders = {}
            if isinstance(data, list):
                for row in data:
                    if not isinstance(row, dict):
                        continue
                    name = str(row.get("FileName", row.get("Name", row.get("FullPath", row.get("Path", "")))))
                    nl = name.lower()
                    if any(nl.endswith(ext) for ext in text_exts):
                        candidates.append(name)
                        parts = name.replace("/", "\\").split("\\")
                        if len(parts) > 2:
                            folder = "\\".join(parts[:-1])
                            folders[folder] = folders.get(folder, 0) + 1
            summary = {
                "filescan_total": len(data) if isinstance(data, list) else 0,
                "text_like_count": len(candidates),
                "top_folders": sorted(folders.items(), key=lambda x: x[1], reverse=True)[:10],
                "samples": candidates[:25]
            }
            def on_dump_ok(res2):
                files = []
                rows = res2["data"]
                count = 0
                total_bytes = 0
                # Support both list and dict structures from dumpfiles
                iterable = []
                if isinstance(rows, list):
                    # If list of lists with 'columns' present alongside, convert
                    iterable = rows
                elif isinstance(rows, dict):
                    # Common keys that may contain per-file rows
                    if "columns" in rows and "rows" in rows and isinstance(rows["rows"], list):
                        cols = rows["columns"]
                        converted = []
                        for r in rows["rows"]:
                            if isinstance(r, list):
                                d = {}
                                for i, v in enumerate(r):
                                    key = cols[i] if i < len(cols) else f"col_{i}"
                                    d[key] = v
                                converted.append(d)
                        iterable = converted
                    else:
                        for k in ("files", "dumped", "results", "items"):
                            v = rows.get(k)
                            if isinstance(v, list):
                                iterable = v
                                break
                for row in iterable:
                    if not isinstance(row, dict):
                        continue
                    dumped = row.get("dumped_file", row.get("output_path", row.get("DumpedPath", row.get("OutputPath", ""))))
                    orig = row.get("file_path", row.get("FilePath", row.get("filename", row.get("Name", row.get("Path", "")))))
                    name_l = str(orig or dumped).lower()
                    if not any(name_l.endswith(ext) for ext in text_exts):
                        continue
                    if dumped and isinstance(dumped, str):
                        try:
                            try:
                                size = os.path.getsize(dumped)
                            except Exception:
                                size = 0
                            total_bytes += size
                            if total_bytes > 200 * 1024 * 1024:
                                break
                            with open(dumped, "rb") as f:
                                buf = f.read(20480)  # 20 KB
                            decoders = ["utf-8", "utf-16le", "utf-16be", "latin-1"]
                            text = ""
                            for enc in decoders:
                                try:
                                    text = buf.decode(enc)
                                    break
                                except Exception:
                                    continue
                            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
                            # embed first 20 kB of text directly so report always shows it
                            embedded = "".join(lines[:400])[:20480]
                            path = orig or dumped
                            fname = os.path.basename(path.replace("/", "\\"))
                            files.append({"path": path, "file_name": fname, "text": embedded})
                            try:
                                os.remove(dumped)
                            except Exception:
                                pass
                            count += 1
                            if count >= 50:
                                break
                        except Exception:
                            continue
                # Cleanup temp directory
                try:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                except Exception:
                    pass
                callback({"plugin": "internal.win.text_scan", "data": {"summary": summary, "files": files}})
            def on_dump_err(err2):
                try:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                except Exception:
                    pass
                callback({"plugin": "internal.win.text_scan", "data": {"summary": summary, "files": []}})
            # Create a temporary directory for dumps and restrict to text-like files
            tmp_dir = tempfile.mkdtemp(prefix="wv_text_")
            # lower-bar regex to catch anything under desktop as well
            dump_args = ["--regex", r".*(desktop|txt|log|cfg|ini|ps1|bat|cmd).*", "--dump-dir", tmp_dir]
            w2 = VolatilityWorker(dump_path, "windows.dumpfiles", additional_args=dump_args)
            w2.finished.connect(on_dump_ok)
            w2.error.connect(on_dump_err)
            t2 = threading.Thread(target=w2.run)
            t2.daemon = True
            t2.start()
        def on_filescan_err(err):
            error_callback({"plugin": "internal.win.text_scan", "message": err["message"]})
        w1 = VolatilityWorker(dump_path, "windows.filescan")
        w1.finished.connect(on_filescan_ok)
        w1.error.connect(on_filescan_err)
        t1 = threading.Thread(target=w1.run)
        t1.daemon = True
        t1.start()

    def _run_cmdline(self, dump_path, callback, error_callback):
        def on_ok(res):
            data = res["data"]
            suspicious = []
            if isinstance(data, list):
                for row in data:
                    if not isinstance(row, dict):
                        continue
                    args = str(row.get("CommandLine", row.get("Args", ""))).lower()
                    pid = row.get("PID", row.get("Pid", None))
                    name = str(row.get("Name", row.get("ImageFileName", "")))
                    if any(k in args for k in ["-enc", "downloadstring", "invoke-webrequest", "bitsadmin", "certutil", "powershell", "http://", "https://", "mshta", "wscript", "cscript"]):
                        suspicious.append({"pid": pid, "name": name, "args": args})
            summary = {"total": len(data) if isinstance(data, list) else 0, "suspicious_count": len(suspicious), "samples": suspicious[:25]}
            callback({"plugin": "internal.win.cmdline", "data": summary})
        def on_err(err):
            error_callback({"plugin": "internal.win.cmdline", "message": err["message"]})
        worker = VolatilityWorker(dump_path, "windows.cmdline")
        worker.finished.connect(on_ok)
        worker.error.connect(on_err)
        t = threading.Thread(target=worker.run)
        t.daemon = True
        t.start()

    def _run_pstree(self, dump_path, callback, error_callback):
        def on_ok(res):
            data = res["data"]
            anomalies = {"orphans": [], "suspicious_parent": []}
            if isinstance(data, list):
                for row in data:
                    if not isinstance(row, dict):
                        continue
                    pid = row.get("PID", row.get("Pid", None))
                    ppid = row.get("PPID", row.get("PPid", None))
                    name = str(row.get("Name", row.get("ImageFileName", ""))).lower()
                    parent = str(row.get("ParentName", row.get("Parent", ""))).lower()
                    if not ppid or ppid == 0:
                        anomalies["orphans"].append({"pid": pid, "name": name})
                    sus_children = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
                    sus_parents = {"explorer.exe", "lsass.exe", "winlogon.exe", "services.exe"}
                    if name in sus_children and parent in sus_parents:
                        anomalies["suspicious_parent"].append({"parent": parent, "child": name, "pid": pid})
            summary = {"anomalies": anomalies, "total": len(data) if isinstance(data, list) else 0}
            callback({"plugin": "internal.win.pstree", "data": summary})
        def on_err(err):
            error_callback({"plugin": "internal.win.pstree", "message": err["message"]})
        worker = VolatilityWorker(dump_path, "windows.pstree")
        worker.finished.connect(on_ok)
        worker.error.connect(on_err)
        t = threading.Thread(target=worker.run)
        t.daemon = True
        t.start()
    def _run_callbacks(self, dump_path, callback, error_callback):
        def on_ok(res):
            data = res["data"]
            summary = {"callbacks_count": 0, "items": []}
            if isinstance(data, list):
                summary["callbacks_count"] = len(data)
                for row in data[:50]:
                    if isinstance(row, dict):
                        summary["items"].append(row)
            callback({"plugin": "internal.win.kernel_scan", "data": summary})
        def on_err(err):
            error_callback({"plugin": "internal.win.kernel_scan", "message": err["message"]})
        worker = VolatilityWorker(dump_path, "windows.callbacks")
        worker.finished.connect(on_ok)
        worker.error.connect(on_err)
        t = threading.Thread(target=worker.run)
        t.daemon = True
        t.start()

    def _run_svcscan(self, dump_path, callback, error_callback):
        def on_ok(res):
            out = []
            data = res["data"]
            if isinstance(data, list):
                for row in data:
                    if not isinstance(row, dict):
                        continue
                    name = str(row.get("Name", ""))
                    path = str(row.get("BinaryPath", row.get("ImagePath", ""))).lower()
                    if "\\appdata\\" in path or "\\temp\\" in path:
                        out.append({"name": name, "path": path})
            callback({"plugin": "internal.win.persistence_scan", "data": {"suspicious_services": out}})
        def on_err(err):
            error_callback({"plugin": "internal.win.persistence_scan", "message": err["message"]})
        worker = VolatilityWorker(dump_path, "windows.svcscan")
        worker.finished.connect(on_ok)
        worker.error.connect(on_err)
        t = threading.Thread(target=worker.run)
        t.daemon = True
        t.start()

    # -------- Linux internal wrappers --------
    def _run_linux_pslist(self, dump_path, callback, error_callback):
        def on_ok(res):
            data = res["data"]
            suspicious = {"tmp_exec": [], "uid_root_shells": []}
            if isinstance(data, list):
                for row in data:
                    if not isinstance(row, dict):
                        continue
                    name = str(row.get("Name", row.get("Comm", ""))).lower()
                    path = str(row.get("Path", row.get("Exe", ""))).lower()
                    uid = row.get("Uid", row.get("UID", None))
                    if "/tmp/" in path or "/dev/shm/" in path:
                        suspicious["tmp_exec"].append({"name": name, "path": path})
                    if uid == 0 and name in {"bash", "sh", "zsh"}:
                        suspicious["uid_root_shells"].append({"name": name, "uid": uid})
            summary = {"total": len(data) if isinstance(data, list) else 0, "suspicious": suspicious}
            callback({"plugin": "internal.linux.pslist", "data": summary})
        def on_err(err):
            error_callback({"plugin": "internal.linux.pslist", "message": err["message"]})
        worker = VolatilityWorker(dump_path, "linux.pslist")
        worker.finished.connect(on_ok)
        worker.error.connect(on_err)
        t = threading.Thread(target=worker.run)
        t.daemon = True
        t.start()

    def _run_linux_bash(self, dump_path, callback, error_callback):
        def on_ok(res):
            data = res["data"]
            suspicious_cmds = []
            indicators = ["curl ", "wget ", "nc ", "netcat", "bash -c", "python -c", "chmod +x", "/tmp/", "base64", "openssl enc", "ssh "]
            if isinstance(data, list):
                for row in data:
                    if not isinstance(row, dict):
                        continue
                    cmd = str(row.get("Command", row.get("History", ""))).lower()
                    if any(ind in cmd for ind in indicators):
                        suspicious_cmds.append(cmd)
            summary = {"entries": len(data) if isinstance(data, list) else 0, "suspicious_count": len(suspicious_cmds), "samples": suspicious_cmds[:20]}
            callback({"plugin": "internal.linux.bash", "data": summary})
        def on_err(err):
            error_callback({"plugin": "internal.linux.bash", "message": err["message"]})
        worker = VolatilityWorker(dump_path, "linux.bash")
        worker.finished.connect(on_ok)
        worker.error.connect(on_err)
        t = threading.Thread(target=worker.run)
        t.daemon = True
        t.start()

    def _run_linux_check_syscall(self, dump_path, callback, error_callback):
        def on_ok(res):
            data = res["data"]
            hooks = 0
            details = []
            if isinstance(data, list):
                for row in data:
                    if not isinstance(row, dict):
                        continue
                    if str(row.get("Hooked", row.get("is_hooked", False))).lower() in {"true", "1"}:
                        hooks += 1
                        details.append(row)
            summary = {"hook_count": hooks, "samples": details[:25]}
            callback({"plugin": "internal.linux.check_syscall", "data": summary})
        def on_err(err):
            error_callback({"plugin": "internal.linux.check_syscall", "message": err["message"]})
        worker = VolatilityWorker(dump_path, "linux.check_syscall")
        worker.finished.connect(on_ok)
        worker.error.connect(on_err)
        t = threading.Thread(target=worker.run)
        t.daemon = True
        t.start()

    def _run_linux_elfs(self, dump_path, callback, error_callback):
        def on_ok(res):
            data = res["data"]
            suspicious = []
            if isinstance(data, list):
                for row in data:
                    if not isinstance(row, dict):
                        continue
                    path = str(row.get("Path", row.get("Module", ""))).lower()
                    if "/tmp/" in path or "/dev/shm/" in path:
                        suspicious.append(path)
            summary = {"modules": len(data) if isinstance(data, list) else 0, "suspicious_modules": suspicious[:25]}
            callback({"plugin": "internal.linux.elfs", "data": summary})
        def on_err(err):
            error_callback({"plugin": "internal.linux.elfs", "message": err["message"]})
        worker = VolatilityWorker(dump_path, "linux.elfs")
        worker.finished.connect(on_ok)
        worker.error.connect(on_err)
        t = threading.Thread(target=worker.run)
        t.daemon = True
        t.start()
