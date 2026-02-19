
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QCheckBox, QLineEdit, QLabel, 
    QScrollArea, QFormLayout, QGroupBox
)
from PyQt6.QtCore import Qt

class PluginConfigWidget(QWidget):
    def __init__(self, plugin_name, options):
        super().__init__()
        self.plugin_name = plugin_name
        self.options = options # List of dicts
        self.widgets = {} # flag -> widget
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Scroll area in case of many options
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        
        content = QWidget()
        form_layout = QFormLayout(content)
        form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        
        if not self.options:
            form_layout.addRow(QLabel("No specific options available."))
        else:
            for opt in self.options:
                flag = opt["flag"]
                help_text = opt.get("help", "")
                arg_syntax = opt.get("arg_syntax", "")
                
                label_text = f"{flag}"
                if arg_syntax:
                    label_text += f" {arg_syntax}"
                
                # Tooltip for help
                
                if opt["is_flag"]:
                    # Checkbox
                    chk = QCheckBox(help_text if help_text else flag)
                    chk.setToolTip(help_text)
                    self.widgets[flag] = chk
                    form_layout.addRow(flag, chk)
                else:
                    # LineEdit
                    le = QLineEdit()
                    le.setPlaceholderText(help_text if help_text else arg_syntax)
                    le.setToolTip(help_text)
                    self.widgets[flag] = le
                    form_layout.addRow(label_text, le)
                    
        scroll.setWidget(content)
        layout.addWidget(scroll)
        
    def get_args(self):
        args = []
        for flag, widget in self.widgets.items():
            if isinstance(widget, QCheckBox):
                if widget.isChecked():
                    args.append(flag)
            elif isinstance(widget, QLineEdit):
                val = widget.text().strip()
                if val:
                    # Handle multiple args if needed, but for now just append
                    args.append(flag)
                    # If val contains spaces, Volatility CLI might expect them as separate args
                    # or as one quoted arg. subprocess handles lists safely.
                    # If the user types "1 2 3", we might want to split?
                    # For now, let's just add it as one string, unless it's obviously a list.
                    # But usually subprocess args should be separate.
                    # If arg_syntax is [PID ...], splitting by space is probably right.
                    if " " in val:
                        args.extend(val.split())
                    else:
                        args.append(val)
        return args
