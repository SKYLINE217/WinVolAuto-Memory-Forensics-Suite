from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QTreeWidget, QTreeWidgetItem, QLabel
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor

class ProcessTreeView(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.risk_pids = set()

    def init_ui(self):
        layout = QVBoxLayout(self)
        
        layout.addWidget(QLabel("Process Tree Visualization"))
        
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Process Name", "PID", "PPID", "Offset", "Threads", "Handles"])
        self.tree.setColumnWidth(0, 200)
        layout.addWidget(self.tree)

    def render_tree(self, pslist_data):
        self.tree.clear()
        
        if not pslist_data:
            return

        # Build a map of PID -> Node
        # And a map of PPID -> list of Children
        
        process_map = {} # PID -> dict
        children_map = {} # PPID -> list of PIDs
        
        # First pass: Index processes
        for row in pslist_data:
            if not isinstance(row, dict): continue
            try:
                pid = int(row.get("PID", 0))
                ppid = int(row.get("PPID", 0))
                process_map[pid] = row
                
                if ppid not in children_map:
                    children_map[ppid] = []
                children_map[ppid].append(pid)
            except ValueError:
                continue

        # Second pass: Build Tree
        # Find roots (processes whose PPID is not in the map, or PPID=0/4 usually)
        # Note: In Windows, System is 4, inherited from 0. 
        # Sometimes processes have PPID that doesn't exist (orphans).
        
        added_pids = set()
        
        def add_node(pid, parent_item):
            if pid in added_pids:
                return
            
            row = process_map.get(pid)
            if not row: return
            
            item = QTreeWidgetItem(parent_item)
            item.setText(0, str(row.get("ImageFileName", "Unknown")))
            item.setText(1, str(pid))
            item.setText(2, str(row.get("PPID", "")))
            item.setText(3, str(row.get("Offset", "")))
            item.setText(4, str(row.get("Threads", "")))
            item.setText(5, str(row.get("Handles", "")))
            
            added_pids.add(pid)
            
            # Add children
            if pid in children_map:
                for child_pid in children_map[pid]:
                    add_node(child_pid, item)
            
            item.setExpanded(True)

        # Find potential roots
        # Roots are nodes where PPID is not in process_map
        roots = []
        for pid, row in process_map.items():
            ppid = int(row.get("PPID", 0))
            if ppid not in process_map:
                roots.append(pid)
        
        # If no roots found (circular?), just take min PID
        if not roots and process_map:
             roots.append(min(process_map.keys()))

        for root_pid in roots:
            add_node(root_pid, self.tree)
            
        # Handle orphans (if any left)
        for pid in process_map:
            if pid not in added_pids:
                add_node(pid, self.tree)
        self.apply_highlights()

    def set_risk_pids(self, pids):
        self.risk_pids = set()
        for x in pids:
            try:
                self.risk_pids.add(int(x))
            except:
                pass
        self.apply_highlights()

    def apply_highlights(self):
        if not self.risk_pids:
            return
        root_count = self.tree.topLevelItemCount()
        for i in range(root_count):
            root = self.tree.topLevelItem(i)
            stack = [root]
            while stack:
                item = stack.pop()
                try:
                    pid = int(item.text(1))
                except:
                    pid = -1
                if pid in self.risk_pids:
                    item.setForeground(0, QColor("#ff4d4f"))
                for j in range(item.childCount()):
                    stack.append(item.child(j))
