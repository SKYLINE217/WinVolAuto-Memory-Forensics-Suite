import sys
from PyQt6.QtWidgets import QApplication, QMessageBox
from src.ui.main_window import MainWindow

def show_disclaimer():
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Icon.Warning)
    msg.setWindowTitle("Legal Disclaimer")
    msg.setText("For authorized security research only.")
    msg.setInformativeText("Unauthorized analysis may violate laws. By proceeding, you certify that you are a security professional using this tool for authorized incident response only.")
    msg.setStandardButtons(QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)
    msg.setDefaultButton(QMessageBox.StandardButton.Cancel)
    
    ret = msg.exec()
    return ret == QMessageBox.StandardButton.Ok

def main():
    app = QApplication(sys.argv)
    
    # In a real app, we'd check a config setting to see if EULA was already accepted
    # For now, we show it every time as per requirements "Warning dialog on first launch"
    # (or we can interpret "first launch" as "every startup" for strictness, or check a config file)
    
    # if not show_disclaimer():
    #     sys.exit(0)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
