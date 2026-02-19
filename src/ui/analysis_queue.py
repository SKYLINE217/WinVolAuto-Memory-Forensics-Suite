from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar
)
from PyQt6.QtCore import Qt

class AnalysisQueue(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.tasks = {} # task_id -> row_index

    def init_ui(self):
        layout = QVBoxLayout(self)
        
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Plugin", "Status", "Progress", "Details"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        layout.addWidget(self.table)

    def add_task(self, plugin_name):
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        self.table.setItem(row, 0, QTableWidgetItem(plugin_name))
        self.table.setItem(row, 1, QTableWidgetItem("Pending"))
        
        pbar = QProgressBar()
        pbar.setRange(0, 0) # Indeterminate
        self.table.setCellWidget(row, 2, pbar)
        
        self.table.setItem(row, 3, QTableWidgetItem(""))
        
        self.tasks[plugin_name] = row
        return row

    def update_status(self, plugin_name, status, details=""):
        if plugin_name in self.tasks:
            row = self.tasks[plugin_name]
            self.table.setItem(row, 1, QTableWidgetItem(status))
            if details:
                self.table.setItem(row, 3, QTableWidgetItem(details))
            
            if status == "Completed":
                # Remove progress bar or set to 100%
                self.table.cellWidget(row, 2).setRange(0, 100)
                self.table.cellWidget(row, 2).setValue(100)
            elif status == "Failed":
                 self.table.cellWidget(row, 2).setRange(0, 100)
                 self.table.cellWidget(row, 2).setValue(0)
