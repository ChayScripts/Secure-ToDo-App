import sys
import json
from datetime import datetime, timedelta
from pathlib import Path
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QTableWidget, QTableWidgetItem, QDialog, QLabel,
                             QLineEdit, QTextEdit, QComboBox, QDateEdit, QSpinBox, QMessageBox,
                             QTabWidget, QHeaderView, QInputDialog, QCheckBox)
from PyQt5.QtCore import Qt, QDate, QTimer, QSize, QItemSelectionModel
from PyQt5.QtGui import QColor, QFont
import base64

class EncryptionHandler:
    @staticmethod
    def encrypt(text, password):
        result = ''
        for i in range(len(text)):
            result += chr(ord(text[i]) ^ ord(password[i % len(password)]))
        return base64.b64encode(result.encode()).decode()
    
    @staticmethod
    def decrypt(encrypted_text, password):
        try:
            decoded = base64.b64decode(encrypted_text.encode()).decode()
            result = ''
            for i in range(len(decoded)):
                result += chr(ord(decoded[i]) ^ ord(password[i % len(password)]))
            return result
        except:
            return None

class TaskDialog(QDialog):
    def __init__(self, parent=None, task=None):
        super().__init__(parent)
        self.task = task
        self.setWindowTitle("Task Details")
        self.setGeometry(100, 100, 600, 550)
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Task (max 256 characters):"))
        self.task_input = QTextEdit()
        self.task_input.setMaximumHeight(60)
        if self.task:
            self.task_input.setPlainText(self.task.get('task', ''))
        layout.addWidget(self.task_input)
        
        layout.addWidget(QLabel("Priority:"))
        self.priority_input = QComboBox()
        self.priority_input.addItems(['Low', 'Medium', 'High', 'Unassigned'])
        if self.task:
            self.priority_input.setCurrentText(self.task.get('priority', 'Unassigned'))
        layout.addWidget(self.priority_input)
        
        layout.addWidget(QLabel("Notes:"))
        self.notes_input = QTextEdit()
        self.notes_input.setMaximumHeight(80)
        if self.task:
            self.notes_input.setPlainText(self.task.get('notes', ''))
        layout.addWidget(self.notes_input)
        
        layout.addWidget(QLabel("Status:"))
        self.status_input = QComboBox()
        self.status_input.addItems(['In Progress', 'Hold', 'Completed'])
        self.status_input.currentTextChanged.connect(self.on_status_changed)
        if self.task:
            self.status_input.setCurrentText(self.task.get('status', 'In Progress'))
        layout.addWidget(self.status_input)
        
        layout.addWidget(QLabel("Start Date:"))
        self.start_date_input = QDateEdit()
        self.start_date_input.setCalendarPopup(True)
        if self.task:
            self.start_date_input.setDate(QDate.fromString(self.task.get('startDate', ''), Qt.ISODate))
        else:
            self.start_date_input.setDate(QDate.currentDate())
        layout.addWidget(self.start_date_input)
        
        layout.addWidget(QLabel("Duration (Days):"))
        self.duration_input = QSpinBox()
        self.duration_input.setMinimum(1)
        self.duration_input.setMaximum(365)
        if self.task:
            self.duration_input.setValue(self.task.get('duration', 1))
        else:
            self.duration_input.setValue(1)
        layout.addWidget(self.duration_input)
        
        layout.addWidget(QLabel("Percent Complete (0-100):"))
        self.percent_input = QSpinBox()
        self.percent_input.setMinimum(0)
        self.percent_input.setMaximum(100)
        self.percent_input.valueChanged.connect(self.on_percent_changed)
        if self.task:
            self.percent_input.setValue(self.task.get('percent', 0))
        else:
            self.percent_input.setValue(0)
        layout.addWidget(self.percent_input)
        
        layout.addWidget(QLabel("Reason for Due:"))
        self.reason_input = QTextEdit()
        self.reason_input.setMaximumHeight(60)
        if self.task:
            self.reason_input.setPlainText(self.task.get('reasonForDue', ''))
        layout.addWidget(self.reason_input)
        
        btn_layout = QHBoxLayout()
        save_btn = QPushButton("💾 Save Task")
        cancel_btn = QPushButton("❌ Cancel")
        save_btn.clicked.connect(self.accept)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
        
        self.setLayout(layout)
    
    def on_status_changed(self, status):
        if status == 'Completed':
            self.percent_input.setValue(100)
    
    def on_percent_changed(self, value):
        if value == 100:
            self.status_input.blockSignals(True)
            self.status_input.setCurrentText('Completed')
            self.status_input.blockSignals(False)
    
    def get_task_data(self):
        return {
            'task': self.task_input.toPlainText()[:256],
            'priority': self.priority_input.currentText(),
            'notes': self.notes_input.toPlainText(),
            'status': self.status_input.currentText(),
            'startDate': self.start_date_input.date().toString(Qt.ISODate),
            'duration': self.duration_input.value(),
            'percent': self.percent_input.value(),
            'reasonForDue': self.reason_input.toPlainText(),
            'lastUpdated': datetime.now().strftime('%Y-%m-%d'),
            'endDate': '',
            'extendedDays': ''
        }

class PasswordSetupDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("🔐 Setup Password")
        self.setGeometry(100, 100, 400, 200)
        self.password = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("First Time Setup - Create Password"))
        layout.addWidget(QLabel("Password (min 4 characters):"))
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)
        
        layout.addWidget(QLabel("Confirm Password:"))
        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.confirm_input)
        
        btn_layout = QHBoxLayout()
        ok_btn = QPushButton("✓ Create")
        ok_btn.clicked.connect(self.validate)
        cancel_btn = QPushButton("✕ Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(ok_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
        
        self.setLayout(layout)
    
    def validate(self):
        pwd = self.password_input.text()
        confirm = self.confirm_input.text()
        
        if len(pwd) < 4:
            QMessageBox.warning(self, "Error", "Password must be at least 4 characters!")
            return
        
        if pwd != confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match!")
            return
        
        self.password = pwd
        self.accept()
    
    def get_password(self):
        return self.password

class PasswordLoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("🔐 Enter Password")
        self.setGeometry(100, 100, 400, 150)
        self.password = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Enter your password:"))
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.returnPressed.connect(self.validate)
        layout.addWidget(self.password_input)
        
        btn_layout = QHBoxLayout()
        ok_btn = QPushButton("🔓 Unlock")
        ok_btn.clicked.connect(self.validate)
        cancel_btn = QPushButton("✕ Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(ok_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
        
        self.setLayout(layout)
        self.password_input.setFocus()
    
    def validate(self):
        pwd = self.password_input.text()
        if len(pwd) < 4:
            QMessageBox.warning(self, "Error", "Invalid password!")
            return
        self.password = pwd
        self.accept()
    
    def get_password(self):
        return self.password

class TodoApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🚀 Todo App")
        self.setGeometry(50, 50, 1600, 900)
        
        self.tasks = []
        self.current_password = ''
        self.selected_task_index = None
        self.config_dir = Path.home() / '.todoapp'
        self.config_dir.mkdir(exist_ok=True)
        self.config_file = self.config_dir / 'config.json'
        
        self.init_ui()
        self.authenticate()
        
        # Auto-save timer
        self.auto_save_timer = QTimer()
        self.auto_save_timer.timeout.connect(self.auto_save)
        self.auto_save_timer.start(30000)
    
    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        
        # Header
        header_label = QLabel("🚀 Todo App")
        header_label.setFont(QFont('Arial', 16, QFont.Bold))
        layout.addWidget(header_label)
        
        self.file_label = QLabel("📁 Storage: Local Encrypted | 🔐 Protected")
        layout.addWidget(self.file_label)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        self.add_btn = QPushButton("➕ Add Task")
        self.add_btn.clicked.connect(self.add_task)
        controls_layout.addWidget(self.add_btn)
        
        self.edit_btn = QPushButton("✏️ Edit Task")
        self.edit_btn.clicked.connect(self.edit_selected_task)
        controls_layout.addWidget(self.edit_btn)
        
        self.delete_btn = QPushButton("🗑️ Delete")
        self.delete_btn.clicked.connect(self.delete_selected)
        controls_layout.addWidget(self.delete_btn)
        
        self.save_btn = QPushButton("💾 Save Updates")
        self.save_btn.clicked.connect(self.save_updates)
        controls_layout.addWidget(self.save_btn)
        
        self.password_btn = QPushButton("🔑 Change Password")
        self.password_btn.clicked.connect(self.change_password)
        controls_layout.addWidget(self.password_btn)
        
        self.lock_btn = QPushButton("🔒 Lock")
        self.lock_btn.clicked.connect(self.lock_app)
        controls_layout.addWidget(self.lock_btn)
        
        layout.addLayout(controls_layout)
        
        # Tabs
        self.tabs = QTabWidget()
        
        # Active Tasks Tab
        self.active_table = QTableWidget()
        self.active_table.setColumnCount(12)
        self.active_table.setHorizontalHeaderLabels([
            'Select', 'Task', 'Priority', 'Notes', 'Status', 'Start Date', 
            'Duration', 'End Date', '% Complete', 'Last Updated', 'Extended Days', 
            'Reason for Due'
        ])
        # Make columns interactive and allow last column to stretch with window
        header = self.active_table.horizontalHeader()
        for i in range(self.active_table.columnCount()):
            header.setSectionResizeMode(i, QHeaderView.Interactive)
        header.setStretchLastSection(True)
        self.active_table.setSelectionBehavior(self.active_table.SelectRows)
        self.active_table.setSelectionMode(self.active_table.MultiSelection)
        self.tabs.addTab(self.active_table, "📋 Active (0)")
        
        # Completed Tasks Tab
        self.completed_table = QTableWidget()
        self.completed_table.setColumnCount(7)
        self.completed_table.setHorizontalHeaderLabels([
            'Select', 'Task', 'Priority', 'Notes', 'Start Date', 
            'Completed Date', 'Duration'
        ])
        header2 = self.completed_table.horizontalHeader()
        for i in range(self.completed_table.columnCount()):
            header2.setSectionResizeMode(i, QHeaderView.Interactive)
        header2.setStretchLastSection(True)
        self.completed_table.setSelectionBehavior(self.completed_table.SelectRows)
        self.completed_table.setSelectionMode(self.completed_table.MultiSelection)
        self.tabs.addTab(self.completed_table, "✅ Completed (0)")
        
        layout.addWidget(self.tabs)
        
        central_widget.setLayout(layout)
    
    def authenticate(self):
        """Handle password authentication"""
        if self.config_file.exists():
            # User exists - show login
            dialog = PasswordLoginDialog(self)
            if dialog.exec_() == QDialog.Accepted:
                password = dialog.get_password()
                if password:
                    self.current_password = password
                    self.load_from_storage()
            else:
                sys.exit()
        else:
            # First time - show setup
            dialog = PasswordSetupDialog(self)
            if dialog.exec_() == QDialog.Accepted:
                password = dialog.get_password()
                if password:
                    self.current_password = password
                    self.save_to_storage()
            else:
                sys.exit()
    
    def load_from_storage(self):
        """Load from local storage"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                
                encrypted_data = config_data.get('tasks')
                if encrypted_data:
                    decrypted = EncryptionHandler.decrypt(encrypted_data, self.current_password)
                    if decrypted:
                        self.tasks = json.loads(decrypted)
        except Exception as e:
            print(f"Load error: {e}")
        
        self.refresh_table()
    
    def auto_save(self):
        """Auto-save every 30 seconds"""
        self.save_to_storage()
    
    def save_to_storage(self):
        """Save to local encrypted storage"""
        try:
            encrypted_data = EncryptionHandler.encrypt(json.dumps(self.tasks), self.current_password)
            config_data = {'tasks': encrypted_data, 'timestamp': datetime.now().isoformat()}
            with open(self.config_file, 'w') as f:
                json.dump(config_data, f)
        except Exception as e:
            print(f"Save error: {e}")
    
    def save_updates(self):
        """Save updates to encrypted local storage"""
        try:
            self.save_to_storage()
            QMessageBox.information(self, "Success", "Updates saved to local storage!")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save: {str(e)}")
    
    def add_task(self):
        """Add new task"""
        dialog = TaskDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            task_data = dialog.get_task_data()
            if task_data['percent'] == 100:
                task_data['status'] = 'Completed'
            self.tasks.append(task_data)
            self.refresh_table()
    
    def edit_selected_task(self):
        """Edit selected task"""
        active_selected = self.active_table.selectionModel().selectedRows()
        completed_selected = self.completed_table.selectionModel().selectedRows()
        
        if not active_selected and not completed_selected:
            QMessageBox.warning(self, "Warning", "Please select a task to edit.")
            return
        
        if len(active_selected) + len(completed_selected) > 1:
            QMessageBox.warning(self, "Warning", "Please select only one task to edit.")
            return
        
        # Get the task index
        if active_selected:
            task_index = self.get_task_index_from_row(active_selected[0].row(), 'active')
        else:
            task_index = self.get_task_index_from_row(completed_selected[0].row(), 'completed')
        
        if task_index >= 0:
            self.edit_task(task_index)
    
    def edit_task(self, index):
        """Edit existing task"""
        if 0 <= index < len(self.tasks):
            dialog = TaskDialog(self, self.tasks[index])
            if dialog.exec_() == QDialog.Accepted:
                task_data = dialog.get_task_data()
                if task_data['percent'] == 100:
                    task_data['status'] = 'Completed'
                self.tasks[index] = task_data
                self.refresh_table()
    
    def delete_selected(self):
        """Delete selected tasks"""
        # Get selected rows from active table
        active_selected = self.active_table.selectionModel().selectedRows()
        completed_selected = self.completed_table.selectionModel().selectedRows()
        
        if not active_selected and not completed_selected:
            QMessageBox.warning(self, "Warning", "Please select tasks to delete.")
            return
        
        total_selected = len(active_selected) + len(completed_selected)
        
        if QMessageBox.question(self, "Confirm", f"Delete {total_selected} task(s)?") == QMessageBox.Yes:
            # Collect all indices to delete
            indices_to_delete = set()
            
            # Get indices from active table
            for row in active_selected:
                task_index = self.get_task_index_from_row(row.row(), 'active')
                if task_index >= 0:
                    indices_to_delete.add(task_index)
            
            # Get indices from completed table
            for row in completed_selected:
                task_index = self.get_task_index_from_row(row.row(), 'completed')
                if task_index >= 0:
                    indices_to_delete.add(task_index)
            
            # Delete in reverse order to maintain correct indices
            for idx in sorted(indices_to_delete, reverse=True):
                if 0 <= idx < len(self.tasks):
                    self.tasks.pop(idx)
            
            self.refresh_table()
    
    def get_task_index_from_row(self, row, table_type):
        """Get the task index from a table row"""
        task_count = 0
        
        for idx, task in enumerate(self.tasks):
            is_completed = task['status'] == 'Completed'
            
            if table_type == 'active' and not is_completed:
                if task_count == row:
                    return idx
                task_count += 1
            elif table_type == 'completed' and is_completed:
                if task_count == row:
                    return idx
                task_count += 1
        
        return -1

    def on_checkbox_state_changed(self, state, row, table):
        sel_model = table.selectionModel()
        index = table.model().index(row, 0)
        if state == Qt.Checked:
            sel_model.select(index, QItemSelectionModel.Select | QItemSelectionModel.Rows)
        else:
            sel_model.select(index, QItemSelectionModel.Deselect | QItemSelectionModel.Rows)
    
    def refresh_table(self):
        """Refresh both tables"""
        self.active_table.setRowCount(0)
        self.completed_table.setRowCount(0)
        
        active_count = 0
        completed_count = 0
        
        for idx, task in enumerate(self.tasks):
            task['lastUpdated'] = datetime.now().strftime('%Y-%m-%d')
            
            try:
                start_date = datetime.strptime(task['startDate'], '%Y-%m-%d')
                end_date = start_date + timedelta(days=task['duration'])
                task['endDate'] = end_date.strftime('%Y-%m-%d')
                
                today = datetime.now()
                diff_days = (today - end_date).days
                task['extendedDays'] = diff_days if diff_days > 0 else ''
            except:
                task['endDate'] = ''
                task['extendedDays'] = ''
            
            # Auto-move to completed if 100%
            if task['percent'] == 100 and task['status'] != 'Completed':
                task['status'] = 'Completed'
            
            if task['status'] == 'Completed':
                self.add_to_completed_table(idx, task)
                completed_count += 1
            else:
                self.add_to_active_table(idx, task)
                active_count += 1
        
        self.tabs.setTabText(0, f"📋 Active ({active_count})")
        self.tabs.setTabText(1, f"✅ Completed ({completed_count})")
        self.save_to_storage()
    
    def add_to_active_table(self, idx, task):
        """Add task to active table"""
        row = self.active_table.rowCount()
        self.active_table.insertRow(row)
        
        # Checkbox - centered
        checkbox = QCheckBox()
        checkbox.setChecked(False)
        checkbox_container = QWidget()
        checkbox_layout = QHBoxLayout(checkbox_container)
        checkbox_layout.setContentsMargins(0, 0, 0, 0)
        checkbox_layout.addStretch()
        checkbox_layout.addWidget(checkbox)
        checkbox_layout.addStretch()
        self.active_table.setCellWidget(row, 0, checkbox_container)
        checkbox.stateChanged.connect(lambda state, r=row, tbl=self.active_table: self.on_checkbox_state_changed(state, r, tbl))
        
        # Columns
        self.active_table.setItem(row, 1, QTableWidgetItem(task['task']))
        
        priority_item = QTableWidgetItem(task['priority'])
        color_map = {'Low': QColor(139, 195, 74), 'Medium': QColor(255, 152, 0), 
                    'High': QColor(244, 67, 54), 'Unassigned': QColor(158, 158, 158)}
        if task.get('priority') in color_map:
            priority_item.setBackground(color_map.get(task['priority']))
            priority_item.setForeground(QColor(255, 255, 255))
        self.active_table.setItem(row, 2, priority_item)
        
        self.active_table.setItem(row, 3, QTableWidgetItem(task.get('notes', '')))
        
        status_item = QTableWidgetItem(task['status'])
        status_color_map = {'In Progress': QColor(33, 150, 243), 'Hold': QColor(255, 152, 0), 
                           'Completed': QColor(76, 175, 80)}
        if task.get('status') in status_color_map:
            status_item.setBackground(status_color_map.get(task['status']))
            status_item.setForeground(QColor(255, 255, 255))
        self.active_table.setItem(row, 4, status_item)
        
        self.active_table.setItem(row, 5, QTableWidgetItem(task.get('startDate', '')))
        self.active_table.setItem(row, 6, QTableWidgetItem(f"{task.get('duration', '')}d" if task.get('duration') != '' else ''))
        self.active_table.setItem(row, 7, QTableWidgetItem(task.get('endDate', '')))
        self.active_table.setItem(row, 8, QTableWidgetItem(f"{task.get('percent', 0)}%"))
        self.active_table.setItem(row, 9, QTableWidgetItem(task.get('lastUpdated', '')))
        
        extended_item = QTableWidgetItem(f"{task['extendedDays']}d" if task.get('extendedDays') else '')
        if task.get('extendedDays'):
            extended_item.setForeground(QColor(244, 67, 54))
        self.active_table.setItem(row, 10, extended_item)
        
        self.active_table.setItem(row, 11, QTableWidgetItem(task.get('reasonForDue', '')))
    
    def add_to_completed_table(self, idx, task):
        """Add task to completed table"""
        row = self.completed_table.rowCount()
        self.completed_table.insertRow(row)
        
        # Checkbox - centered
        checkbox = QCheckBox()
        checkbox.setChecked(False)
        checkbox_container = QWidget()
        checkbox_layout = QHBoxLayout(checkbox_container)
        checkbox_layout.setContentsMargins(0, 0, 0, 0)
        checkbox_layout.addStretch()
        checkbox_layout.addWidget(checkbox)
        checkbox_layout.addStretch()
        self.completed_table.setCellWidget(row, 0, checkbox_container)
        checkbox.stateChanged.connect(lambda state, r=row, tbl=self.completed_table: self.on_checkbox_state_changed(state, r, tbl))
        
        # Columns
        self.completed_table.setItem(row, 1, QTableWidgetItem(task.get('task', '')))
        
        priority_item = QTableWidgetItem(task.get('priority', ''))
        color_map = {'Low': QColor(139, 195, 74), 'Medium': QColor(255, 152, 0), 
                    'High': QColor(244, 67, 54), 'Unassigned': QColor(158, 158, 158)}
        if task.get('priority') in color_map:
            priority_item.setBackground(color_map.get(task['priority']))
            priority_item.setForeground(QColor(255, 255, 255))
        self.completed_table.setItem(row, 2, priority_item)
        
        self.completed_table.setItem(row, 3, QTableWidgetItem(task.get('notes', '')))
        self.completed_table.setItem(row, 4, QTableWidgetItem(task.get('startDate', '')))
        self.completed_table.setItem(row, 5, QTableWidgetItem(task.get('lastUpdated', '')))
        self.completed_table.setItem(row, 6, QTableWidgetItem(f"{task.get('duration', '')}d" if task.get('duration') != '' else ''))
    
    def change_password(self):
        """Change password"""
        new_pwd, ok1 = QInputDialog.getText(self, "New Password", "Enter new password (min 4):", QLineEdit.Password)
        if ok1 and len(new_pwd) >= 4:
            confirm_pwd, ok2 = QInputDialog.getText(self, "Confirm", "Confirm password:", QLineEdit.Password)
            if ok2:
                if new_pwd == confirm_pwd:
                    self.current_password = new_pwd
                    self.save_to_storage()
                    QMessageBox.information(self, "Success", "Password changed!")
                else:
                    QMessageBox.warning(self, "Error", "Passwords don't match!")
    
    def lock_app(self):
        """Lock the app"""
        if QMessageBox.question(self, "Lock", "Lock And Exit the app?") == QMessageBox.Yes:
            self.save_to_storage()
            sys.exit()

def main():
    import sys, os
    from PyQt5.QtGui import QIcon
    from PyQt5.QtWidgets import QApplication

    if hasattr(sys, '_MEIPASS'):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))

    icon_path = os.path.join(base_path, "Todo_app.ico")

    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon(icon_path))
    window = TodoApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
