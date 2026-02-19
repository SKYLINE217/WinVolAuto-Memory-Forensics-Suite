from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QTreeWidget, QTreeWidgetItem, QTextEdit, QSplitter
)

class ResultsView(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        
        splitter = QSplitter()
        
        # Left: Plugin List
        self.plugin_tree = QTreeWidget()
        self.plugin_tree.setHeaderLabel("Completed Plugins")
        self.plugin_tree.itemClicked.connect(self.show_details)
        splitter.addWidget(self.plugin_tree)
        
        # Right: Details
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        splitter.addWidget(self.details_text)
        
        layout.addWidget(splitter)
        self.results_data = {}

    def add_result(self, plugin, data):
        self.results_data[plugin] = data
        item = QTreeWidgetItem([plugin])
        self.plugin_tree.addTopLevelItem(item)

    def show_details(self, item, column):
        plugin = item.text(0)
        if plugin in self.results_data:
            import json
            self.details_text.setText(json.dumps(self.results_data[plugin], indent=4))
