
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, 
    QFileDialog, QCheckBox, QGroupBox, QListWidget, QSplitter,
    QTreeWidget, QTreeWidgetItem, QTreeWidgetItemIterator, QStackedWidget, QLineEdit,
    QScrollArea, QFrame, QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QColor, QIcon

from src.backend.plugin_discovery import PluginDiscovery
from src.ui.plugin_config import PluginConfigWidget

class PluginLoader(QThread):
    loaded = pyqtSignal(dict) # plugins dict
    
    def run(self):
        pd = PluginDiscovery()
        plugins = pd.get_all_plugins()
        self.loaded.emit(plugins)

class OptionsLoader(QThread):
    loaded = pyqtSignal(str, list) # plugin_name, options
    
    def __init__(self, plugin_name):
        super().__init__()
        self.plugin_name = plugin_name
        
    def run(self):
        pd = PluginDiscovery()
        options = pd.get_plugin_options(self.plugin_name)
        self.loaded.emit(self.plugin_name, options)

class Dashboard(QWidget):
    analysis_requested = pyqtSignal(str, dict) # file_path, options (including plugins list)

    def __init__(self):
        super().__init__()
        self.plugin_configs = {} # plugin_name -> PluginConfigWidget
        self.selected_file = None
        self.init_ui()
        
        # Start loading plugins
        self.status_label.setText("Loading plugins...")
        self.loader = PluginLoader()
        self.loader.loaded.connect(self.on_plugins_loaded)
        self.loader.start()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Header
        header = QLabel("WinVolAuto Professional")
        header_font = QFont("Segoe UI", 24, QFont.Weight.Bold)
        header.setFont(header_font)
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("color: #0078d4; margin-bottom: 10px;")
        main_layout.addWidget(header)
        
        sub_header = QLabel("Advanced Memory Forensics Suite")
        sub_font = QFont("Segoe UI", 12)
        sub_header.setFont(sub_font)
        sub_header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub_header.setStyleSheet("color: #666; margin-bottom: 20px;")
        main_layout.addWidget(sub_header)

        # Splitter content
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # LEFT PANEL: Plugin Selection
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        lbl_plugins = QLabel("Available Plugins")
        lbl_plugins.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        left_layout.addWidget(lbl_plugins)
        
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search plugins...")
        self.search_box.textChanged.connect(self.filter_plugins)
        left_layout.addWidget(self.search_box)
        
        self.plugin_tree = QTreeWidget()
        self.plugin_tree.setHeaderLabels(["Plugin", "Description"])
        self.plugin_tree.setColumnWidth(0, 250)
        self.plugin_tree.itemChanged.connect(self.on_plugin_checked)
        self.plugin_tree.currentItemChanged.connect(self.on_plugin_selected)
        left_layout.addWidget(self.plugin_tree)
        
        splitter.addWidget(left_panel)
        
        # RIGHT PANEL: Configuration
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(10, 0, 0, 0)
        
        # File Selection
        file_group = QGroupBox("Target Memory Image")
        file_layout = QHBoxLayout()
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setPlaceholderText("Select memory dump file...")
        self.file_path_edit.setReadOnly(True)
        btn_browse = QPushButton("Browse...")
        btn_browse.clicked.connect(self.select_file)
        file_layout.addWidget(self.file_path_edit)
        file_layout.addWidget(btn_browse)
        file_group.setLayout(file_layout)
        right_layout.addWidget(file_group)
        
        # Plugin Configuration
        self.config_group = QGroupBox("Plugin Configuration")
        config_layout = QVBoxLayout()
        self.config_stack = QStackedWidget()
        
        # Default empty config
        self.lbl_no_config = QLabel("Select a plugin to configure options.")
        self.lbl_no_config.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.config_stack.addWidget(self.lbl_no_config)
        
        config_layout.addWidget(self.config_stack)
        self.config_group.setLayout(config_layout)
        right_layout.addWidget(self.config_group)
        
        # Global Options
        global_group = QGroupBox("Global Options")
        global_layout = QVBoxLayout()
        self.chk_vt = QCheckBox("Enable VirusTotal Integration (Risk Based)")
        self.chk_vt.setChecked(True)
        global_layout.addWidget(self.chk_vt)
        self.chk_ai = QCheckBox("Enable AI Risk Probability")
        self.chk_ai.setChecked(True)
        global_layout.addWidget(self.chk_ai)
        global_group.setLayout(global_layout)
        right_layout.addWidget(global_group)
        
        # Status & Action
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #666;")
        right_layout.addWidget(self.status_label)
        
        self.start_btn = QPushButton("Start Analysis")
        self.start_btn.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #0078d4;
                color: white;
                padding: 12px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #106ebe;
            }
            QPushButton:disabled {
                background-color: #ccc;
            }
        """)
        self.start_btn.clicked.connect(self.start_analysis)
        self.start_btn.setEnabled(False)
        right_layout.addWidget(self.start_btn)
        
        splitter.addWidget(right_panel)
        splitter.setSizes([300, 500])
        
        main_layout.addWidget(splitter)
        
    def select_file(self):
        fname, _ = QFileDialog.getOpenFileName(
            self, "Open Memory Dump", "", "Memory Files (*.raw *.mem *.dmp *.vmem *.elf *.core);;All Files (*)"
        )
        if fname:
            self.selected_file = fname
            self.file_path_edit.setText(fname)
            self.start_btn.setEnabled(True)
            
            # Auto-expand appropriate plugin category
            fname_lower = fname.lower()
            target_category = "windows" # default
            
            if fname_lower.endswith(".elf") or fname_lower.endswith(".core") or "linux" in fname_lower:
                target_category = "linux"
            elif "mac" in fname_lower or "darwin" in fname_lower:
                target_category = "mac"
                
            # Find and expand the category
            for i in range(self.plugin_tree.topLevelItemCount()):
                item = self.plugin_tree.topLevelItem(i)
                is_target = item.text(0).lower() == target_category
                
                if is_target:
                    item.setExpanded(True)
                    self.plugin_tree.scrollToItem(item, QTreeWidget.ScrollHint.PositionAtTop)
                else:
                    item.setExpanded(False)
                    
                # Smart Check/Uncheck:
                # Uncheck all in non-target categories
                # Check defaults in target category
                for j in range(item.childCount()):
                    child = item.child(j)
                    plugin_name = child.text(0)
                    
                    if not is_target:
                        child.setCheckState(0, Qt.CheckState.Unchecked)
                    else:
                        # Auto-select common plugins for the target OS
                        defaults = []
                        if target_category == "windows":
                            defaults = ["windows.pslist", "windows.psscan", "windows.malfind", "windows.netscan"]
                        elif target_category == "linux":
                            defaults = ["linux.pslist", "linux.bash", "linux.check_syscall", "linux.elfs"]
                        elif target_category == "mac":
                            defaults = ["mac.pslist", "mac.bash", "mac.check_syscall"]
                            
                        if plugin_name in defaults:
                            child.setCheckState(0, Qt.CheckState.Checked)
                        else:
                            child.setCheckState(0, Qt.CheckState.Unchecked)

    def on_plugins_loaded(self, plugins):
        if "error" in plugins:
            self.status_label.setText(f"Error loading plugins: {plugins['error']}")
            return
            
        self.plugin_tree.clear()
        
        # Group by category (windows, linux, mac, other)
        groups = {
            "windows": QTreeWidgetItem(["Windows", ""]),
            "linux": QTreeWidgetItem(["Linux", ""]),
            "mac": QTreeWidgetItem(["Mac", ""]),
            "other": QTreeWidgetItem(["Other", ""])
        }
        
        for name, desc in plugins.items():
            category = "other"
            if name.startswith("windows"): category = "windows"
            elif name.startswith("linux"): category = "linux"
            elif name.startswith("mac"): category = "mac"
            
            item = QTreeWidgetItem([name, desc])
            item.setCheckState(0, Qt.CheckState.Unchecked)
            # Default check some common plugins
            if name in ["windows.pslist", "windows.psscan", "windows.malfind", "windows.netscan"]:
                item.setCheckState(0, Qt.CheckState.Checked)
                
            groups[category].addChild(item)
            
        # Inject internal Windows plugins group
        sumit_group = QTreeWidgetItem(["WinVolAuto (Sumit K.K.)", "Created by developer of this Project [Sumit K.K.]"])
        for pname, pdesc in [
            ("internal.win.cmdline", "Win: Command Lines (Sumit K.K.)"),
            ("internal.win.pstree", "Win: Process Tree (Sumit K.K.)"),
            ("internal.win.kernel_scan", "Win: Kernel Scan (Sumit K.K.)"),
            ("internal.win.persistence_scan", "Win: Persistence Scan (Sumit K.K.)"),
            ("internal.win.text_scan", "Win: Text Files & Folder Triage"),
        ]:
            child = QTreeWidgetItem([pname, pdesc])
            child.setCheckState(0, Qt.CheckState.Unchecked)
            sumit_group.addChild(child)
        self.plugin_tree.addTopLevelItem(sumit_group)
        sumit_group.setExpanded(True)

        # Inject internal Linux plugins group
        sumit_linux = QTreeWidgetItem(["WinVolAuto Linux (Sumit K.K.)", "Linux-focused internal analysis plugins"])
        for pname, pdesc in [
            ("internal.linux.pslist", "Linux: Process List Triage"),
            ("internal.linux.bash", "Linux: Bash History Triage"),
            ("internal.linux.check_syscall", "Linux: Syscall Hook Scan"),
            ("internal.linux.elfs", "Linux: ELF Module Scan"),
        ]:
            child = QTreeWidgetItem([pname, pdesc])
            child.setCheckState(0, Qt.CheckState.Unchecked)
            sumit_linux.addChild(child)
        self.plugin_tree.addTopLevelItem(sumit_linux)
        sumit_linux.setExpanded(True)
        
        for key in ["windows", "linux", "mac", "other"]:
            if groups[key].childCount() > 0:
                self.plugin_tree.addTopLevelItem(groups[key])
                groups[key].setExpanded(key == "windows")
                
        self.status_label.setText(f"Loaded {len(plugins)} plugins.")

    def filter_plugins(self, text):
        search_text = text.lower()
        
        # Iterate top level items (categories)
        for i in range(self.plugin_tree.topLevelItemCount()):
            category_item = self.plugin_tree.topLevelItem(i)
            category_visible = False
            
            for j in range(category_item.childCount()):
                child = category_item.child(j)
                name = child.text(0).lower()
                desc = child.text(1).lower()
                
                if search_text in name or search_text in desc:
                    child.setHidden(False)
                    category_visible = True
                else:
                    child.setHidden(True)
            
            category_item.setHidden(not category_visible)
            if category_visible:
                category_item.setExpanded(True)

    def on_plugin_checked(self, item, column):
        # Maybe auto-select it?
        pass

    def on_plugin_selected(self, current, previous):
        if not current:
            return
            
        plugin_name = current.text(0)
        if not plugin_name or current.childCount() > 0:
            self.config_group.setTitle("Plugin Configuration")
            self.config_stack.setCurrentWidget(self.lbl_no_config)
            return
            
        self.config_group.setTitle(f"Configuration: {plugin_name}")
        
        # Check if we already have a config widget
        if plugin_name in self.plugin_configs:
            self.config_stack.setCurrentWidget(self.plugin_configs[plugin_name])
        else:
            # Load options async
            self.status_label.setText(f"Loading options for {plugin_name}...")
            # Show loading placeholder
            # For now, create loader
            loader = OptionsLoader(plugin_name)
            loader.loaded.connect(self.on_options_loaded)
            # We need to keep reference to loader to prevent GC? 
            # In PyQt QThread, yes.
            self.current_loader = loader 
            loader.start()

    def on_options_loaded(self, plugin_name, options):
        self.status_label.setText("Ready")
        widget = PluginConfigWidget(plugin_name, options)
        self.plugin_configs[plugin_name] = widget
        self.config_stack.addWidget(widget)
        self.config_stack.setCurrentWidget(widget)

    def start_analysis(self):
        if not self.selected_file:
            QMessageBox.warning(self, "Error", "Please select a memory dump file.")
            return
            
        # Collect selected plugins and their args
        selected_plugins = []
        
        iterator = QTreeWidgetItemIterator(self.plugin_tree, QTreeWidgetItemIterator.IteratorFlag.Checked)
        while iterator.value():
            item = iterator.value()
            if item.childCount() == 0: # Leaf node
                name = item.text(0)
                args = []
                if name in self.plugin_configs:
                    args = self.plugin_configs[name].get_args()
                selected_plugins.append({"name": name, "args": args})
            iterator += 1
            
        if not selected_plugins:
            QMessageBox.warning(self, "Error", "Please select at least one plugin to run.")
            return
            
        options = {
            "plugins": selected_plugins,
            "vt": self.chk_vt.isChecked(),
            "ai_enabled": self.chk_ai.isChecked(),
            # Legacy fields for compatibility if needed, but we should update main_window
            "auto_profile": False, 
            "yara": False # We can add yara plugin manually if selected
        }
        
        self.analysis_requested.emit(self.selected_file, options)
