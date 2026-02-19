from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QLabel, QMessageBox
)
from src.backend.report_generator import ReportGenerator

class ReportsTab(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.generator = ReportGenerator()
        self.last_results = None
        self.last_risk = None

    def init_ui(self):
        layout = QVBoxLayout(self)
        
        layout.addWidget(QLabel("Export Analysis Reports"))
        
        self.btn_json = QPushButton("Export JSON Report")
        self.btn_json.clicked.connect(self.export_json)
        layout.addWidget(self.btn_json)
        
        self.btn_pdf = QPushButton("Export PDF Report")
        self.btn_pdf.clicked.connect(self.export_pdf)
        layout.addWidget(self.btn_pdf)
        
        layout.addStretch()

    def set_data(self, results, risk_report, file_path=None, capabilities=None):
        self.last_results = results
        self.last_risk = risk_report
        self.current_file = file_path
        self.last_caps = capabilities or []

    def export_json(self):
        if not self.last_results:
            QMessageBox.warning(self, "Error", "No analysis data available.")
            return
            
        try:
            path = self.generator.generate_json(self.last_results, self.last_risk, self.current_file, capabilities=self.last_caps)
            QMessageBox.information(self, "Success", f"JSON Report saved to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def export_pdf(self):
        if not self.last_results:
            QMessageBox.warning(self, "Error", "No analysis data available.")
            return
            
        try:
            path = self.generator.generate_pdf(self.last_results, self.last_risk, self.current_file, capabilities=self.last_caps)
            QMessageBox.information(self, "Success", f"PDF Report saved to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
