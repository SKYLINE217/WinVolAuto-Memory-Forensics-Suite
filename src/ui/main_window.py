from PyQt6.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QTabWidget, QLabel, QMessageBox
from PyQt6.QtCore import Qt
from src.ui.dashboard import Dashboard
from src.ui.analysis_queue import AnalysisQueue
from src.ui.results_view import ResultsView
from src.ui.reports_tab import ReportsTab
from src.ui.process_tree import ProcessTreeView
from src.backend.volatility_engine import VolatilityEngine
from src.backend.risk_analyzer import RiskAnalyzer
from src.backend.vt_handler import VirusTotalHandler
from src.backend.capability_analyzer import CapabilityAnalyzer
from src.utils.config import load_config
import os
import glob

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WinVolAuto - Professional Malware Forensics")
        self.resize(1280, 850)
        self.apply_styles()
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.layout = QVBoxLayout(self.central_widget)
        self.layout.setContentsMargins(0, 0, 0, 0)
        
        # Header (removed, Dashboard has header now)
        # But we might want a global menu or toolbar later.
        
        # Tabs
        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)
        
        # Initialize tabs
        self.dashboard = Dashboard()
        self.dashboard.analysis_requested.connect(self.start_analysis)
        
        self.queue = AnalysisQueue()
        self.results = ResultsView()
        self.process_tree = ProcessTreeView()
        self.reports_tab = ReportsTab()
        
        self.tabs.addTab(self.dashboard, "Dashboard")
        self.tabs.addTab(self.queue, "Analysis Queue")
        self.tabs.addTab(self.process_tree, "Process Tree")
        self.tabs.addTab(self.results, "Results")
        self.tabs.addTab(self.reports_tab, "Reports")
        
        # Status Bar
        self.statusBar().showMessage("Ready")
        
        self.engine = VolatilityEngine()
        self.risk_analyzer = RiskAnalyzer()
        self.cap_analyzer = CapabilityAnalyzer()
        
        self.current_dump = None
        self.analysis_options = {}
        self.pending_plugins = []
        self.collected_results = {}

    def apply_styles(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QWidget {
                background-color: #1e1e1e;
                color: #ffffff;
                font-family: 'Segoe UI', sans-serif;
                font-size: 14px;
            }
            QTabWidget::pane {
                border: 1px solid #333;
                background: #252526;
            }
            QTabBar::tab {
                background: #2d2d30;
                color: #ccc;
                padding: 10px 20px;
                border: 1px solid #333;
                border-bottom: none;
            }
            QTabBar::tab:selected {
                background: #0078d4;
                color: white;
            }
            QTabBar::tab:hover {
                background: #3e3e42;
            }
            QGroupBox {
                border: 1px solid #3e3e42;
                margin-top: 20px;
                font-weight: bold;
                color: #0078d4;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QLineEdit {
                background-color: #252526;
                border: 1px solid #3e3e42;
                color: #fff;
                padding: 5px;
            }
            QTreeWidget, QListWidget {
                background-color: #252526;
                border: 1px solid #3e3e42;
                color: #fff;
            }
            QHeaderView::section {
                background-color: #2d2d30;
                color: #fff;
                padding: 5px;
                border: 1px solid #3e3e42;
            }
            QScrollBar:vertical {
                background: #252526;
                width: 12px;
            }
            QScrollBar::handle:vertical {
                background: #3e3e42;
                min-height: 20px;
            }
            QLabel {
                color: #ddd;
            }
            QCheckBox {
                spacing: 5px;
                color: #ddd;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
        """)

    def start_analysis(self, dump_path, options):
        self.current_dump = dump_path
        self.analysis_options = options
        self.collected_results = {}
        self.tabs.setCurrentWidget(self.queue)
        
        self.statusBar().showMessage(f"Analyzing {dump_path}...")
        
        # Build plugin list
        self.pending_plugins = []
        
        if "plugins" in options and isinstance(options["plugins"], list):
            # New workflow: User selected plugins
            self.pending_plugins = list(options["plugins"])
        else:
            # Fallback legacy workflow
            if options.get("auto_profile", True):
                 self.pending_plugins.append({"name": "windows.info"})
            
            workflow = ["windows.pslist", "windows.psscan", "windows.netscan", "windows.malfind", "windows.dlllist", "windows.handles", "windows.svcscan", "windows.callbacks"]
            for p in workflow:
                self.pending_plugins.append({"name": p})
                
            if options.get("yara", False):
                rule_path = os.path.abspath("resources/rules/example.yar")
                self.pending_plugins.append({
                    "name": "windows.vadyarascan.VadYaraScan", 
                    "args": ["--yara-file", rule_path]
                })
        
        self.run_next_plugin()

    def run_next_plugin(self):
        if not self.pending_plugins:
            self.finish_analysis()
            return

        plugin_info = self.pending_plugins.pop(0)
        plugin_name = plugin_info["name"]
        args = plugin_info.get("args", [])
        
        self.queue.add_task(plugin_name)
        self.queue.update_status(plugin_name, "Running")
        
        # Define callbacks
        def on_success(result):
            self.queue.update_status(result["plugin"], "Completed")
            self.results.add_result(result["plugin"], result["data"])
            self.collected_results[result["plugin"]] = result["data"]
            
            if result["plugin"] == "windows.pslist":
                self.process_tree.render_tree(result["data"])
                
            self.run_next_plugin()
            
        def on_error(error_data):
            msg = error_data["message"]
            plugin_name = error_data["plugin"]
            self.statusBar().showMessage(f"Error in {plugin_name}: {msg}")
            self.queue.update_status(plugin_name, "Failed", msg)
            self.run_next_plugin()

        self.engine.run_plugin(self.current_dump, plugin_name, on_success, on_error, additional_args=args)

    def finish_analysis(self):
        self.statusBar().showMessage("Analysis Complete. Calculating Risk...")
        
        if "ai_enabled" in self.analysis_options:
            self.risk_analyzer.ai_enabled = bool(self.analysis_options["ai_enabled"])
        risk_report = self.risk_analyzer.analyze(self.collected_results)
        
        # Pass data to reports tab
        caps = self.cap_analyzer.analyze(self.collected_results, risk_report)
        self.reports_tab.set_data(self.collected_results, risk_report, self.current_dump, capabilities=caps)
        self.results.add_result("Risk Summary", risk_report)
        self.results.add_result("Capabilities", caps)
        high_prob_pids = [pid for pid, p in risk_report.get("pid_probabilities", {}).items() if p >= 0.6]
        union_pids = set(risk_report.get("suspicious_pids", [])) | set(high_prob_pids)
        self.process_tree.set_risk_pids(list(union_pids))
        
        # Show Summary
        prob_pct = int(round(risk_report.get('probability', 0.0) * 100))
        summary = f"Risk Level: {risk_report['level']} (Score: {risk_report['total_score']})\nRisk Probability: {prob_pct}%\n\n"
        if risk_report["details"]:
            summary += "Findings:\n" + "\n".join(f"- {d}" for d in risk_report["details"])
        else:
            summary += "No high-risk indicators found."
            
        QMessageBox.information(self, "Analysis Complete", summary)
        self.statusBar().showMessage(f"Analysis Finished. Risk Level: {risk_report['level']}")

        # Check for VirusTotal Submission
        if self.analysis_options.get("vt", False) and risk_report.get("suspicious_pids"):
            pids = risk_report["suspicious_pids"]
            reply = QMessageBox.question(
                self, "VirusTotal Submission", 
                f"Found {len(pids)} suspicious processes. Submit extracted files to VirusTotal?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.start_vt_workflow(pids)

    def start_vt_workflow(self, pids):
        self.vt_pids = list(pids)
        self.vt_results = []
        config = load_config()
        api_key = config.get("virustotal_api_key", "")
        
        if not api_key:
            QMessageBox.warning(self, "Error", "No VirusTotal API Key configured in config.json")
            return
            
        self.vt_handler = VirusTotalHandler(api_key)
        self.run_next_vt_pid()

    def run_next_vt_pid(self):
        if not self.vt_pids:
            # All done
            self.show_vt_results()
            return
            
        pid = self.vt_pids.pop(0)
        self.statusBar().showMessage(f"VT: Dumping files for PID {pid}...")
        
        # We need to dump files first
        # We'll use windows.dumpfiles
        # Output to a temp dir or specific dir
        output_dir = os.path.abspath(f"dumps/pid_{pid}")
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        plugin_name = "windows.dumpfiles"
        args = ["--pid", str(pid), "--output-dir", output_dir]
        
        self.queue.add_task(f"VT Dump PID {pid}")
        self.queue.update_status(f"VT Dump PID {pid}", "Dumping")
        
        def on_dump_success(result):
            self.queue.update_status(f"VT Dump PID {pid}", "Scanning")
            # In a real app, run this in a thread to avoid freezing
            self.scan_dumped_files(pid, output_dir)
            
        def on_dump_error(error):
            self.queue.update_status(f"VT Dump PID {pid}", "Failed", error["message"])
            self.run_next_vt_pid()
            
        self.engine.run_plugin(self.current_dump, plugin_name, on_dump_success, on_dump_error, additional_args=args)

    def scan_dumped_files(self, pid, output_dir):
        # Find files
        files = glob.glob(os.path.join(output_dir, "*"))
        if not files:
            self.queue.update_status(f"VT Dump PID {pid}", "No Files")
            self.run_next_vt_pid()
            return
            
        results = []
        for f in files:
            # Skip large files
            if os.path.getsize(f) > 10 * 1024 * 1024: 
                continue
                
            file_hash = self.vt_handler.calculate_hash(f)
            if file_hash:
                res = self.vt_handler.scan_file_hash(file_hash)
                results.append(res)
        
        self.vt_results.append({"pid": pid, "results": results})
        self.queue.update_status(f"VT Dump PID {pid}", "Scanned")
        self.run_next_vt_pid()

    def show_vt_results(self):
        msg = "VirusTotal Results:\n\n"
        count = 0
        for item in self.vt_results:
            pid = item["pid"]
            for res in item["results"]:
                if "error" in res:
                    continue
                if res.get("malicious", 0) > 0:
                    msg += f"PID {pid} - {res['hash'][:8]}... : {res['malicious']} Malicious\n"
                    count += 1
        
        if count == 0:
            msg += "No malicious files detected (or hash not found)."
            
        QMessageBox.information(self, "VirusTotal Scan Complete", msg)
