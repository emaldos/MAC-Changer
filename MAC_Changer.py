import sys
import os
import json
import logging
import subprocess
import re
import random
import time

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QComboBox, QLineEdit, QTextEdit, QLabel, QMessageBox, QDialog,
    QInputDialog, QTableWidget, QTableWidgetItem, QHeaderView, QScrollArea
)
from PyQt6.QtGui import QPalette, QColor, QRegularExpressionValidator, QIntValidator
from PyQt6.QtCore import QRegularExpression, QObject, pyqtSignal, QThread

# Global variable to hold the sudo password for the current session.
SUDO_PASSWORD = ""

#############################################
# Helper Functions
#############################################

def get_interfaces():
    """Retrieve available network interfaces (excluding loopback) using the 'ip link show' command."""
    try:
        result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
        interfaces = []
        for line in result.stdout.splitlines():
            match = re.match(r"^\d+:\s+([\w@]+):", line)
            if match:
                iface = match.group(1).split('@')[0]
                if iface != "lo":
                    interfaces.append(iface)
        return interfaces
    except Exception:
        return []

def get_current_mac_iface(iface):
    """Get the current MAC address of the given interface."""
    try:
        result = subprocess.run(["ip", "link", "show", iface], capture_output=True, text=True)
        output = result.stdout
        mac_search = re.search(r"link/ether ([0-9a-fA-F:]{17})", output)
        if mac_search:
            return mac_search.group(1)
        else:
            return "00:00:00:00:00:00"
    except Exception:
        return "00:00:00:00:00:00"

def append_auto_change(iface, old_mac, new_mac):
    """Append a change record to auto_changes.json."""
    filename = "auto_changes.json"
    data = []
    if os.path.exists(filename):
        with open(filename, "r") as f:
            try:
                data = json.load(f)
            except:
                data = []
    change_entry = {"interface": iface, "old_mac": old_mac, "new_mac": new_mac}
    data.append(change_entry)
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

def append_smart_change(iface, old_mac, new_mac):
    """Append a change record to changes_smart.json."""
    filename = "changes_smart.json"
    data = []
    if os.path.exists(filename):
        with open(filename, "r") as f:
            try:
                data = json.load(f)
            except:
                data = []
    change_entry = {"interface": iface, "old_mac": old_mac, "new_mac": new_mac}
    data.append(change_entry)
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

#############################################
# Dialogs for Logs and Changes Display & Clearing
#############################################

class LogDialog(QDialog):
    def __init__(self, file_path, filter_str=None, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self.filter_str = filter_str  # if provided, only lines containing this will be shown
        self.initUI()
        self.loadLog()
        
    def initUI(self):
        self.setWindowTitle("Log Viewer")
        self.resize(800, 400)
        layout = QVBoxLayout()
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        layout.addWidget(self.text_edit)
        
        btn_layout = QHBoxLayout()
        self.clear_btn = QPushButton("Clear Log")
        self.close_btn = QPushButton("Close")
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addWidget(self.close_btn)
        layout.addLayout(btn_layout)
        
        self.setLayout(layout)
        
        self.clear_btn.clicked.connect(self.clearLog)
        self.close_btn.clicked.connect(self.accept)
        
    def loadLog(self):
        if os.path.exists(self.file_path):
            with open(self.file_path, "r") as f:
                lines = f.readlines()
            if self.filter_str:
                lines = [line for line in lines if self.filter_str in line]
            self.text_edit.setPlainText("".join(lines))
        else:
            self.text_edit.setPlainText("No log file found.")
            
    def clearLog(self):
        with open(self.file_path, "w") as f:
            f.write("")
        self.text_edit.setPlainText("")

class ChangesDialog(QDialog):
    def __init__(self, file_path, title="Changes", parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self.setWindowTitle(title)
        self.resize(600, 400)
        self.initUI()
        self.loadChanges()
        
    def initUI(self):
        layout = QVBoxLayout()
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        layout.addWidget(self.text_edit)
        
        btn_layout = QHBoxLayout()
        self.clear_btn = QPushButton("Clear Changes")
        self.close_btn = QPushButton("Close")
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addWidget(self.close_btn)
        layout.addLayout(btn_layout)
        
        self.setLayout(layout)
        
        self.clear_btn.clicked.connect(self.clearChanges)
        self.close_btn.clicked.connect(self.accept)
        
    def loadChanges(self):
        if os.path.exists(self.file_path):
            with open(self.file_path, "r") as f:
                try:
                    changes = json.load(f)
                except Exception:
                    changes = []
            if changes:
                lines = []
                for change in changes:
                    iface = change.get("interface", "N/A")
                    old_mac = change.get("old_mac", "N/A")
                    new_mac = change.get("new_mac", "N/A")
                    lines.append(f"{iface} | {old_mac} | {new_mac}")
                self.text_edit.setPlainText("\n".join(lines))
            else:
                self.text_edit.setPlainText("No changes recorded.")
        else:
            self.text_edit.setPlainText("No changes file found.")
            
    def clearChanges(self):
        with open(self.file_path, "w") as f:
            json.dump([], f, indent=4)
        self.text_edit.setPlainText("")

#############################################
# Dialogs for Company Editing (for Smart MAC)
#############################################

class EditCompanyDialog(QDialog):
    def __init__(self, company_name="", ouis=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add/Edit Company")
        self.company_name = company_name
        self.ouis = ouis if ouis is not None else []
        self.initUI()
        
    def initUI(self):
        layout = QVBoxLayout()
        
        # Company name input
        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("Company Name:"))
        self.name_edit = QLineEdit(self.company_name)
        name_layout.addWidget(self.name_edit)
        layout.addLayout(name_layout)
        
        self.resize(600, 400)
        
        # Label for OUIs
        layout.addWidget(QLabel("MAC Prefixes (OUIs) - Format: XX:XX:XX:"))
        
        # Scrollable area to display added OUIs
        self.oui_container = QVBoxLayout()
        for oui in self.ouis:
            self.addOUIRow(oui)
        container_widget = QWidget()
        container_widget.setLayout(self.oui_container)
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(container_widget)
        layout.addWidget(scroll_area)
        
        # Input area to add a new OUI
        new_layout = QHBoxLayout()
        self.new_oui_edit = QLineEdit()
        self.new_oui_edit.setPlaceholderText("Enter new OUI (e.g., 001122)")
        # Set maxLength to 8 characters to allow "00:00:00"
        self.new_oui_edit.setMaxLength(8)
        # Use a regex that allows partial input and auto-formatting (0 to 6 hex digits with optional colons)
        regex = QRegularExpression(r"^([0-9A-Fa-f]{2}:){0,2}[0-9A-Fa-f]{0,2}$")
        validator = QRegularExpressionValidator(regex)
        self.new_oui_edit.setValidator(validator)
        self.new_oui_edit.textChanged.connect(self.autoFormatNewOUI)
        new_layout.addWidget(self.new_oui_edit)
        self.add_oui_btn = QPushButton("Add OUI")
        new_layout.addWidget(self.add_oui_btn)
        self.add_oui_btn.clicked.connect(self.handleAddOUI)
        layout.addLayout(new_layout)
        
        # OK and Cancel buttons
        btn_layout = QHBoxLayout()
        self.ok_btn = QPushButton("OK")
        self.cancel_btn = QPushButton("Cancel")
        btn_layout.addWidget(self.ok_btn)
        btn_layout.addWidget(self.cancel_btn)
        layout.addLayout(btn_layout)
        
        self.ok_btn.clicked.connect(self.accept)
        self.cancel_btn.clicked.connect(self.reject)
        
        self.setLayout(layout)
        
    def autoFormatNewOUI(self, text):
        # Remove any non-hex characters and limit to 6 hex digits
        raw = re.sub(r"[^0-9A-Fa-f]", "", text)[:6]
        # Insert colon after every 2 characters
        formatted = ":".join(raw[i:i+2] for i in range(0, len(raw), 2))
        if formatted != text:
            cursor_pos = self.new_oui_edit.cursorPosition()
            self.new_oui_edit.blockSignals(True)
            self.new_oui_edit.setText(formatted)
            self.new_oui_edit.setCursorPosition(len(formatted))
            self.new_oui_edit.blockSignals(False)
        
    def addOUIRow(self, oui):
        # Create a horizontal layout with a label for the OUI and a delete button
        row = QHBoxLayout()
        label = QLabel(oui)
        row.addWidget(label)
        del_btn = QPushButton("X")
        del_btn.setFixedWidth(30)
        del_btn.clicked.connect(lambda: self.removeOUIRow(row))
        row.addWidget(del_btn)
        self.oui_container.addLayout(row)
        
    def removeOUIRow(self, row_layout):
        # Remove all widgets in the row and remove the row layout
        for i in reversed(range(row_layout.count())):
            widget = row_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)
        self.oui_container.removeItem(row_layout)
        
    def handleAddOUI(self):
        text = self.new_oui_edit.text().strip()
        # Remove colons and ensure exactly 6 hex digits are entered
        if text and len(text.replace(":", "")) == 6:
            self.addOUIRow(text)
            self.new_oui_edit.clear()
        
    def getData(self):
        company_name = self.name_edit.text().strip()
        ouis = []
        for i in range(self.oui_container.count()):
            layout_item = self.oui_container.itemAt(i)
            if layout_item is not None:
                label = layout_item.itemAt(0).widget()
                if label:
                    ouis.append(label.text())
        return company_name, ouis


class EditCompaniesDialog(QDialog):
    def __init__(self, companies, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Companies")
        self.companies = companies  # dictionary {company: [ouis]}
        self.initUI()
        self.loadTable()
        
    def initUI(self):
        layout = QVBoxLayout()
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Company", "OUIs", "Edit", "Delete"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)
        
        btn_layout = QHBoxLayout()
        self.close_btn = QPushButton("Close")
        btn_layout.addWidget(self.close_btn)
        layout.addLayout(btn_layout)
        
        self.close_btn.clicked.connect(self.accept)
        # Increase the width of the dialog to 800 pixels
        self.resize(800, 400)
        self.setLayout(layout)
        
    def loadTable(self):
        self.table.setRowCount(0)
        for company, ouis in self.companies.items():
            row_position = self.table.rowCount()
            self.table.insertRow(row_position)
            self.table.setItem(row_position, 0, QTableWidgetItem(company))
            self.table.setItem(row_position, 1, QTableWidgetItem(", ".join(ouis)))
            edit_btn = QPushButton("# Edit")
            edit_btn.clicked.connect(lambda ch, comp=company: self.editCompany(comp))
            self.table.setCellWidget(row_position, 2, edit_btn)
            del_btn = QPushButton("X Delete")
            del_btn.clicked.connect(lambda ch, comp=company: self.deleteCompany(comp))
            self.table.setCellWidget(row_position, 3, del_btn)
        
    def editCompany(self, company):
        ouis = self.companies.get(company, [])
        dialog = EditCompanyDialog(company, ouis, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_name, new_ouis = dialog.getData()
            if new_name != company:
                self.companies.pop(company, None)
            self.companies[new_name] = new_ouis
            self.saveCompanies()
            self.loadTable()
        
    def deleteCompany(self, company):
        reply = QMessageBox.question(self, "Delete Company", f"Are you sure you want to delete {company}?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.companies.pop(company, None)
            self.saveCompanies()
            self.loadTable()
    
    def saveCompanies(self):
        with open("company_ouis.json", "w") as f:
            json.dump(self.companies, f, indent=4)

class EditCompaniesDialog(QDialog):
    def __init__(self, companies, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Companies")
        self.companies = companies  # dictionary {company: [ouis]}
        self.initUI()
        self.loadTable()
        
    def initUI(self):
        layout = QVBoxLayout()
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Company", "OUIs", "Edit", "Delete"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)
        
        btn_layout = QHBoxLayout()
        self.close_btn = QPushButton("Close")
        btn_layout.addWidget(self.close_btn)
        layout.addLayout(btn_layout)
        
        self.close_btn.clicked.connect(self.accept)
        # Increase the width of the dialog
        self.resize(800, 400)
        self.setLayout(layout)
        
    def loadTable(self):
        self.table.setRowCount(0)
        for company, ouis in self.companies.items():
            row_position = self.table.rowCount()
            self.table.insertRow(row_position)
            self.table.setItem(row_position, 0, QTableWidgetItem(company))
            self.table.setItem(row_position, 1, QTableWidgetItem(", ".join(ouis)))
            edit_btn = QPushButton("# Edit")
            edit_btn.clicked.connect(lambda ch, comp=company: self.editCompany(comp))
            self.table.setCellWidget(row_position, 2, edit_btn)
            del_btn = QPushButton("X Delete")
            del_btn.clicked.connect(lambda ch, comp=company: self.deleteCompany(comp))
            self.table.setCellWidget(row_position, 3, del_btn)
        
    def editCompany(self, company):
        ouis = self.companies.get(company, [])
        dialog = EditCompanyDialog(company, ouis, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_name, new_ouis = dialog.getData()
            if new_name != company:
                self.companies.pop(company, None)
            self.companies[new_name] = new_ouis
            self.saveCompanies()
            self.loadTable()
        
    def deleteCompany(self, company):
        reply = QMessageBox.question(self, "Delete Company", f"Are you sure you want to delete {company}?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.companies.pop(company, None)
            self.saveCompanies()
            self.loadTable()
    
    def saveCompanies(self):
        with open("company_ouis.json", "w") as f:
            json.dump(self.companies, f, indent=4)


#############################################
# Worker Class for Auto MAC Flooding Attack
#############################################

class AutoMACWorker(QObject):
    update_notification = pyqtSignal(str)
    finished = pyqtSignal()
    error_signal = pyqtSignal(str)
    
    def __init__(self, iface, total_changes, total_duration, sudo_password):
        super().__init__()
        self.iface = iface
        self.total_changes = total_changes
        self.total_duration = total_duration
        self.sudo_password = sudo_password
        self.running = True

    def generate_random_mac(self):
        first_octet = random.randint(0, 255) & 0xFE  
        mac = [first_octet] + [random.randint(0, 255) for _ in range(5)]
        return ":".join("{:02X}".format(x) for x in mac)

    def run(self):
        try:
            delay = self.total_duration / self.total_changes if self.total_changes > 0 else 0
        except Exception as e:
            self.error_signal.emit(f"Invalid schedule parameters: {e}")
            return

        for i in range(self.total_changes):
            if not self.running:
                break
            old_mac = get_current_mac_iface(self.iface)
            new_mac = self.generate_random_mac()
            try:
                subprocess.run(["sudo", "-S", "ip", "link", "set", self.iface, "down"],
                               input=self.sudo_password+"\n", text=True, check=True)
                subprocess.run(["sudo", "-S", "ip", "link", "set", self.iface, "address", new_mac],
                               input=self.sudo_password+"\n", text=True, check=True)
                subprocess.run(["sudo", "-S", "ip", "link", "set", self.iface, "up"],
                               input=self.sudo_password+"\n", text=True, check=True)
                log_msg = f"[ + ] {self.iface}: {new_mac}"
                self.update_notification.emit(log_msg)
                logging.info(f"auto: MAC changed for {self.iface} to {new_mac}")
                append_auto_change(self.iface, old_mac, new_mac)
            except Exception as e:
                self.error_signal.emit(f"[ - ] error: {str(e)}")
                break
            time.sleep(delay)
        self.finished.emit()

#############################################
# Sudo Password Tab
#############################################

class SudoPasswordTab(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout()
        explanation = QLabel(
            "Please enter your sudo password.\n\n"
            "This password is required to change network interface settings.\n"
            "Note: The sudo password will not be stored or saved permanently."
        )
        layout.addWidget(explanation)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password_input)
        
        self.set_password_btn = QPushButton("Set Sudo Password")
        layout.addWidget(self.set_password_btn)
        self.set_password_btn.clicked.connect(self.set_password)
        
        self.notification_area = QTextEdit()
        self.notification_area.setReadOnly(True)
        layout.addWidget(self.notification_area)
        
        self.setLayout(layout)
    
    def set_password(self):
        global SUDO_PASSWORD
        pwd = self.password_input.text().strip()
        if pwd:
            SUDO_PASSWORD = pwd
            self.notification_area.append("[ + ] Sudo password has been set for this session.")
        else:
            self.notification_area.append("[ - ] Please enter a valid sudo password.")

#############################################
# Manual MAC Tab
#############################################

class ManualMACTab(QWidget):
    def __init__(self):
        super().__init__()
        self.default_mac_file = "default_mac_address.json"
        self.changes_file = "changes_tracking.json"
        self.log_file = "mac_changer.log"
        self.initUI()
        self.setup_logging()

    def initUI(self):
        layout = QVBoxLayout()

        layout.addWidget(QLabel("Select Interface:"))
        self.iface_combo = QComboBox()
        self.iface_combo.addItems(get_interfaces())
        layout.addWidget(self.iface_combo)

        layout.addWidget(QLabel("Enter New MAC Address:"))
        self.mac_entry = QLineEdit()
        self.mac_entry.setMaxLength(17)
        regex = QRegularExpression(r"^[0-9A-Fa-f:]{0,17}$")
        validator = QRegularExpressionValidator(regex)
        self.mac_entry.setValidator(validator)
        self.mac_entry.textChanged.connect(self.auto_format_mac)
        layout.addWidget(self.mac_entry)

        note_label = QLabel("Note: Use a valid unicast MAC (format: XX:XX:XX:XX:XX:XX). The first octet must be even.")
        info_button = QPushButton("MAC Address Info")
        info_button.clicked.connect(self.show_mac_info)
        note_layout = QHBoxLayout()
        note_layout.addWidget(note_label)
        note_layout.addWidget(info_button)
        layout.addLayout(note_layout)

        btn_layout = QHBoxLayout()
        self.change_btn = QPushButton("Start Changing")
        self.reset_btn = QPushButton("Reset to Default")
        btn_layout.addWidget(self.change_btn)
        btn_layout.addWidget(self.reset_btn)
        layout.addLayout(btn_layout)

        layout.addWidget(QLabel("Notifications:"))
        self.notification_area = QTextEdit()
        self.notification_area.setReadOnly(True)
        layout.addWidget(self.notification_area)

        extra_btn_layout = QHBoxLayout()
        self.display_log_btn = QPushButton("Display Log")
        self.display_changes_btn = QPushButton("Display Changes")
        extra_btn_layout.addWidget(self.display_log_btn)
        extra_btn_layout.addWidget(self.display_changes_btn)
        layout.addLayout(extra_btn_layout)

        self.setLayout(layout)

        self.change_btn.clicked.connect(self.start_changing)
        self.reset_btn.clicked.connect(self.reset_to_default)
        self.display_log_btn.clicked.connect(self.display_log)
        self.display_changes_btn.clicked.connect(self.display_changes)

    def setup_logging(self):
        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format='%(asctime)s - %(message)s'
        )

    def append_notification(self, message):
        self.notification_area.append(message)

    def auto_format_mac(self, text):
        text_no_colons = re.sub(r"[^0-9A-Fa-f]", "", text)[:12]
        formatted = ":".join(text_no_colons[i:i+2] for i in range(0, len(text_no_colons), 2))
        if formatted != text:
            cursor_pos = self.mac_entry.cursorPosition()
            self.mac_entry.blockSignals(True)
            self.mac_entry.setText(formatted)
            self.mac_entry.setCursorPosition(min(cursor_pos+1, len(formatted)))
            self.mac_entry.blockSignals(False)

    def show_mac_info(self):
        info_text = (
            "A valid MAC address must have 6 pairs of hexadecimal digits separated by colons.\n"
            "For example: 12:34:56:78:9A:BC\n\n"
            "Important: The first octet (first two hex digits) must be even to ensure a valid unicast MAC."
        )
        QMessageBox.information(self, "MAC Address Format Info", info_text)

    def start_changing(self):
        iface = self.iface_combo.currentText()
        new_mac = self.mac_entry.text().strip()
        if not new_mac or len(new_mac) != 17:
            self.append_notification("[ - ] error: Please enter a valid MAC address in format XX:XX:XX:XX:XX:XX")
            return

        first_octet = new_mac.split(":")[0]
        try:
            if int(first_octet, 16) % 2 != 0:
                self.append_notification("[ - ] error: Invalid MAC address. The first octet must be even.")
                return
        except Exception:
            self.append_notification("[ - ] error: Unable to parse MAC address.")
            return

        if not SUDO_PASSWORD:
            self.append_notification("[ - ] error: Sudo password not set. Please set it in the Sudo Password tab.")
            return

        default_mac = self.get_current_mac(iface)
        if not self.is_default_saved(iface) and default_mac != "00:00:00:00:00:00":
            self.save_default_mac(iface, default_mac)

        try:
            subprocess.run(["sudo", "-S", "ip", "link", "set", iface, "down"],
                           input=SUDO_PASSWORD+"\n", text=True, check=True)
            self.append_notification(f"[ + ] Successfully brought down interface {iface}")
            logging.info(f"Interface {iface} brought down")
        except Exception as e:
            err = str(e)
            self.append_notification(f"[ - ] error while bringing down {iface}: {err}")
            logging.error(f"Error bringing down interface {iface}: {err}")
            return

        try:
            subprocess.run(["sudo", "-S", "ip", "link", "set", iface, "address", new_mac],
                           input=SUDO_PASSWORD+"\n", text=True, check=True)
            self.append_notification(f"[ + ] Successfully changed MAC for {iface}")
            logging.info(f"MAC changed for {iface} to {new_mac}")
        except Exception as e:
            err = str(e)
            self.append_notification(f"[ - ] error changing MAC: {err}")
            logging.error(f"Error changing MAC for {iface}: {err}")
            self.append_notification("[ - ] Attempting to restore default MAC address...")
            self.reset_to_default()
            return

        try:
            subprocess.run(["sudo", "-S", "ip", "link", "set", iface, "up"],
                           input=SUDO_PASSWORD+"\n", text=True, check=True)
            self.append_notification(f"[ + ] Interface {iface} is up")
            logging.info(f"Interface {iface} brought up")
        except Exception as e:
            err = str(e)
            self.append_notification(f"[ - ] error bringing up interface {iface}: {err}")
            logging.error(f"Error bringing up interface {iface}: {err}")
            return

        current_mac = self.get_current_mac(iface)
        if current_mac.lower() == new_mac.lower():
            self.append_notification(f"[ + ] New MAC Address for {iface} is {new_mac}")
            self.save_change_tracking(iface, default_mac, new_mac)
        else:
            self.append_notification(f"[ - ] error: MAC change verification failed. Current MAC: {current_mac}")
            logging.error(f"MAC change verification failed for {iface}")

    def reset_to_default(self):
        iface = self.iface_combo.currentText()
        if not SUDO_PASSWORD:
            self.append_notification("[ - ] error: Sudo password not set. Please set it in the Sudo Password tab.")
            return

        default_mac = self.get_default_mac(iface)
        if not default_mac:
            self.append_notification(f"[ - ] error: Default MAC not found for {iface}")
            return

        try:
            subprocess.run(["sudo", "-S", "ip", "link", "set", iface, "down"],
                           input=SUDO_PASSWORD+"\n", text=True, check=True)
            self.append_notification(f"[ + ] Successfully brought down interface {iface}")
            logging.info(f"Interface {iface} brought down for reset")
        except Exception as e:
            err = str(e)
            self.append_notification(f"[ - ] error while bringing down {iface} for reset: {err}")
            logging.error(f"Error bringing down interface {iface} for reset: {err}")
            return

        try:
            subprocess.run(["sudo", "-S", "ip", "link", "set", iface, "address", default_mac],
                           input=SUDO_PASSWORD+"\n", text=True, check=True)
            self.append_notification(f"[ + ] Successfully reset MAC for {iface}")
            logging.info(f"MAC reset for {iface} to {default_mac}")
        except Exception as e:
            err = str(e)
            self.append_notification(f"[ - ] error resetting MAC: {err}")
            logging.error(f"Error resetting MAC for {iface}: {err}")
            return

        try:
            subprocess.run(["sudo", "-S", "ip", "link", "set", iface, "up"],
                           input=SUDO_PASSWORD+"\n", text=True, check=True)
            self.append_notification(f"[ + ] Interface {iface} is up")
            logging.info(f"Interface {iface} brought up after reset")
        except Exception as e:
            err = str(e)
            self.append_notification(f"[ - ] error bringing up interface {iface} after reset: {err}")
            logging.error(f"Error bringing up interface {iface} after reset: {err}")
            return

    def get_current_mac(self, iface):
        try:
            result = subprocess.run(["ip", "link", "show", iface], capture_output=True, text=True)
            output = result.stdout
            mac_search = re.search(r"link/ether ([0-9a-fA-F:]{17})", output)
            if mac_search:
                return mac_search.group(1)
            else:
                return "00:00:00:00:00:00"
        except Exception:
            return "00:00:00:00:00:00"

    def is_default_saved(self, iface):
        if os.path.exists(self.default_mac_file):
            with open(self.default_mac_file, "r") as f:
                try:
                    data = json.load(f)
                    return iface in data
                except:
                    return False
        return False

    def save_default_mac(self, iface, mac):
        data = {}
        if os.path.exists(self.default_mac_file):
            with open(self.default_mac_file, "r") as f:
                try:
                    data = json.load(f)
                except:
                    data = {}
        data[iface] = mac
        with open(self.default_mac_file, "w") as f:
            json.dump(data, f, indent=4)
        self.append_notification(f"[ + ] Default MAC for {iface} saved as {mac}")

    def get_default_mac(self, iface):
        if os.path.exists(self.default_mac_file):
            with open(self.default_mac_file, "r") as f:
                try:
                    data = json.load(f)
                    return data.get(iface)
                except:
                    return None
        return None

    def save_change_tracking(self, iface, old_mac, new_mac):
        data = []
        if os.path.exists(self.changes_file):
            with open(self.changes_file, "r") as f:
                try:
                    data = json.load(f)
                except:
                    data = []
        change_entry = {"interface": iface, "old_mac": old_mac, "new_mac": new_mac}
        data.append(change_entry)
        with open(self.changes_file, "w") as f:
            json.dump(data, f, indent=4)

    def display_log(self):
        dlg = LogDialog(self.log_file, parent=self)
        dlg.exec()

    def display_changes(self):
        dlg = ChangesDialog(self.changes_file, title="Manual MAC Changes", parent=self)
        dlg.exec()

#############################################
# Auto MAC Tab
#############################################

class AutoMACTab(QWidget):
    def __init__(self):
        super().__init__()
        self.thread = None
        self.worker = None
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout()

        layout.addWidget(QLabel("Select Interface:"))
        self.iface_combo = QComboBox()
        self.iface_combo.addItems(get_interfaces())
        layout.addWidget(self.iface_combo)

        self.single_change_btn = QPushButton("Start Random Change for MAC")
        layout.addWidget(self.single_change_btn)
        
        schedule_layout = QHBoxLayout()
        self.changes_edit = QLineEdit()
        self.changes_edit.setPlaceholderText("Total number of changes (integer)")
        self.changes_edit.setValidator(QIntValidator(1, 1000000))
        schedule_layout.addWidget(self.changes_edit)
        self.duration_edit = QLineEdit()
        self.duration_edit.setPlaceholderText("Total duration in seconds (integer)")
        self.duration_edit.setValidator(QIntValidator(1, 1000000))
        schedule_layout.addWidget(self.duration_edit)
        layout.addLayout(schedule_layout)
        
        recommended_label = QLabel("Recommended: Do not exceed 20 changes per second (i.e. delay >= 0.05 sec).")
        layout.addWidget(recommended_label)
        
        self.flood_attack_btn = QPushButton("Start MAC Flooding Attack")
        layout.addWidget(self.flood_attack_btn)
        
        self.reset_default_btn = QPushButton("Reset Default MAC")
        layout.addWidget(self.reset_default_btn)
        
        layout.addWidget(QLabel("Notifications:"))
        self.notification_area = QTextEdit()
        self.notification_area.setReadOnly(True)
        layout.addWidget(self.notification_area)
        
        auto_btn_layout = QHBoxLayout()
        self.display_auto_log_btn = QPushButton("Display Auto Log")
        self.display_auto_changes_btn = QPushButton("Display Auto Changes")
        auto_btn_layout.addWidget(self.display_auto_log_btn)
        auto_btn_layout.addWidget(self.display_auto_changes_btn)
        layout.addLayout(auto_btn_layout)
        
        self.setLayout(layout)
        
        self.single_change_btn.clicked.connect(self.start_single_change)
        self.flood_attack_btn.clicked.connect(self.start_flooding_attack)
        self.reset_default_btn.clicked.connect(self.reset_default_mac)
        self.display_auto_log_btn.clicked.connect(self.display_auto_log)
        self.display_auto_changes_btn.clicked.connect(self.display_auto_changes)
    
    def append_notification(self, message):
        self.notification_area.append(message)
    
    def start_single_change(self):
        iface = self.iface_combo.currentText()
        if not SUDO_PASSWORD:
            self.append_notification("[ - ] error: Sudo password not set. Please set it in the Sudo Password tab.")
            return
        
        old_mac = get_current_mac_iface(iface)
        new_mac = AutoMACWorker(iface, 1, 1, SUDO_PASSWORD).generate_random_mac()
        
        try:
            subprocess.run(["sudo", "-S", "ip", "link", "set", iface, "down"],
                           input=SUDO_PASSWORD+"\n", text=True, check=True)
            subprocess.run(["sudo", "-S", "ip", "link", "set", iface, "address", new_mac],
                           input=SUDO_PASSWORD+"\n", text=True, check=True)
            subprocess.run(["sudo", "-S", "ip", "link", "set", iface, "up"],
                           input=SUDO_PASSWORD+"\n", text=True, check=True)
            msg = f"[ + ] {iface}: {new_mac}"
            self.append_notification(msg)
            logging.info(f"auto: MAC changed for {iface} to {new_mac}")
            append_auto_change(iface, old_mac, new_mac)
        except Exception as e:
            err = str(e)
            self.append_notification(f"[ - ] error: {err}")
    
    def start_flooding_attack(self):
        iface = self.iface_combo.currentText()
        try:
            total_changes = int(self.changes_edit.text().strip())
            total_duration = int(self.duration_edit.text().strip())
        except Exception:
            self.append_notification("[ - ] error: Please enter valid numbers for schedule.")
            return

        if not SUDO_PASSWORD:
            self.append_notification("[ - ] error: Sudo password not set. Please set it in the Sudo Password tab.")
            return

        delay = total_duration / total_changes if total_changes else 0
        if delay < 0.05:
            self.append_notification("[ ! ] Warning: High frequency requested. Recommended delay is at least 0.05 sec per change.")

        self.thread = QThread()
        self.worker = AutoMACWorker(iface, total_changes, total_duration, SUDO_PASSWORD)
        self.worker.moveToThread(self.thread)
        self.worker.update_notification.connect(self.append_notification)
        self.worker.error_signal.connect(self.handle_worker_error)
        self.worker.finished.connect(self.handle_worker_finished)
        self.thread.started.connect(self.worker.run)
        self.thread.start()
    
    def reset_default_mac(self):
        iface = self.iface_combo.currentText()
        if not SUDO_PASSWORD:
            self.append_notification("[ - ] error: Sudo password not set. Please set it in the Sudo Password tab.")
            return
        default_mac = None
        if os.path.exists("default_mac_address.json"):
            with open("default_mac_address.json", "r") as f:
                try:
                    data = json.load(f)
                    default_mac = data.get(iface)
                except Exception:
                    default_mac = None
        if not default_mac:
            self.append_notification(f"[ - ] error: Default MAC not found for {iface}")
            return
        try:
            subprocess.run(["sudo", "-S", "ip", "link", "set", iface, "down"],
                           input=SUDO_PASSWORD+"\n", text=True, check=True)
            self.append_notification(f"[ + ] Successfully brought down interface {iface}")
        except Exception as e:
            self.append_notification(f"[ - ] error while bringing down {iface} for reset: {str(e)}")
            return
        try:
            subprocess.run(["sudo", "-S", "ip", "link", "set", iface, "address", default_mac],
                           input=SUDO_PASSWORD+"\n", text=True, check=True)
            self.append_notification(f"[ + ] Successfully reset MAC for {iface}")
        except Exception as e:
            self.append_notification(f"[ - ] error resetting MAC: {str(e)}")
            return
        try:
            subprocess.run(["sudo", "-S", "ip", "link", "set", iface, "up"],
                           input=SUDO_PASSWORD+"\n", text=True, check=True)
            self.append_notification(f"[ + ] Interface {iface} is up")
        except Exception as e:
            self.append_notification(f"[ - ] error bringing up interface {iface} after reset: {str(e)}")
            return

    def handle_worker_error(self, error_msg):
        self.append_notification(error_msg)
        if self.thread:
            self.thread.quit()
            self.thread.wait()
    
    def handle_worker_finished(self):
        self.append_notification("[ + ] MAC Flooding Attack Was Successfully Done!")
        if self.thread:
            self.thread.quit()
            self.thread.wait()
    
    def display_auto_log(self):
        dlg = LogDialog("mac_changer.log", filter_str="auto:", parent=self)
        dlg.exec()
    
    def display_auto_changes(self):
        dlg = ChangesDialog("auto_changes.json", title="Auto MAC Changes", parent=self)
        dlg.exec()

#############################################
# Smart MAC Tab
#############################################

class SmartMACTab(QWidget):
    def __init__(self):
        super().__init__()
        self.company_file = "company_ouis.json"
        self.changes_file = "changes_smart.json"
        self.initUI()
        self.loadCompanies()

    def initUI(self):
        layout = QVBoxLayout()
        # Interface selection for Smart MAC
        layout.addWidget(QLabel("Select Interface:"))
        self.iface_combo = QComboBox()
        self.iface_combo.addItems(get_interfaces())
        layout.addWidget(self.iface_combo)
        
        # Company selection
        layout.addWidget(QLabel("Select Company:"))
        self.company_combo = QComboBox()
        layout.addWidget(self.company_combo)
        
        # OUI selection
        layout.addWidget(QLabel("Select OUI:"))
        self.oui_combo = QComboBox()
        layout.addWidget(self.oui_combo)
        self.company_combo.currentIndexChanged.connect(self.updateOUICombo)
        
        # Buttons for company management
        btn_layout = QHBoxLayout()
        self.add_company_btn = QPushButton("Add Company")
        self.edit_companies_btn = QPushButton("Edit Companies")
        btn_layout.addWidget(self.add_company_btn)
        btn_layout.addWidget(self.edit_companies_btn)
        layout.addLayout(btn_layout)
        self.add_company_btn.clicked.connect(self.addCompany)
        self.edit_companies_btn.clicked.connect(self.editCompanies)
        
        # Button to generate Smart MAC address
        self.generate_btn = QPushButton("Generate Random MAC for Company")
        layout.addWidget(self.generate_btn)
        self.generate_btn.clicked.connect(self.generateSmartMAC)
        
        # Reset to default MAC button
        self.reset_btn = QPushButton("Reset to Default MAC")
        layout.addWidget(self.reset_btn)
        self.reset_btn.clicked.connect(self.resetToDefault)
        
        # Notifications
        layout.addWidget(QLabel("Notifications:"))
        self.notification_area = QTextEdit()
        self.notification_area.setReadOnly(True)
        layout.addWidget(self.notification_area)
        
        # Display buttons for Smart log and changes
        btn_layout2 = QHBoxLayout()
        self.display_smart_log_btn = QPushButton("Display Smart Log")
        self.display_smart_changes_btn = QPushButton("Display Smart Changes")
        btn_layout2.addWidget(self.display_smart_log_btn)
        btn_layout2.addWidget(self.display_smart_changes_btn)
        layout.addLayout(btn_layout2)
        self.display_smart_log_btn.clicked.connect(self.displaySmartLog)
        self.display_smart_changes_btn.clicked.connect(self.displaySmartChanges)
        
        self.setLayout(layout)
    
    def loadCompanies(self):
        if not os.path.exists(self.company_file):
            default_companies = {
                "iPhone": ["00:1A:2B", "00:1B:3C"],
                "Samsung": ["00:16:3E"],
                "Dell": ["00:1D:4F"]
            }
            with open(self.company_file, "w") as f:
                json.dump(default_companies, f, indent=4)
        with open(self.company_file, "r") as f:
            try:
                self.companies = json.load(f)
            except:
                self.companies = {}
        self.company_combo.clear()
        for comp in self.companies.keys():
            self.company_combo.addItem(comp)
        self.updateOUICombo()
    
    def updateOUICombo(self):
        company = self.company_combo.currentText()
        self.oui_combo.clear()
        if company in self.companies:
            for oui in self.companies[company]:
                self.oui_combo.addItem(oui)
    
    def addCompany(self):
        # Instead of using QInputDialog, create and show your custom EditCompanyDialog:
        dialog = EditCompanyDialog("", [], self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_company_name, new_ouis = dialog.getData()
            if new_company_name:
                # Save them to your dictionary and JSON file
                if new_company_name not in self.companies:
                    self.companies[new_company_name] = []
                self.companies[new_company_name].extend(new_ouis)
                # Remove duplicates if you like:
                self.companies[new_company_name] = list(set(self.companies[new_company_name]))
                
                # Write out to company_ouis.json
                with open(self.company_file, "w") as f:
                    json.dump(self.companies, f, indent=4)
                
                # Reload companies in the UI
                self.loadCompanies()
                self.append_notification(
                    f"[ smar: + ] Added/Updated company {new_company_name} with OUIs: {', '.join(new_ouis)}"
                )

    def editCompanies(self):
        dialog = EditCompaniesDialog(self.companies, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            with open(self.company_file, "r") as f:
                self.companies = json.load(f)
            self.loadCompanies()
            self.append_notification("[ smar: + ] Companies updated.")
    
    def generateSmartMAC(self):
        iface = self.iface_combo.currentText()
        if not iface:
            self.append_notification("[ smar: - ] error: No interface selected.")
            return
        if not SUDO_PASSWORD:
            self.append_notification("[ smar: - ] error: Sudo password not set. Please set it in the Sudo Password tab.")
            return
        company = self.company_combo.currentText()
        selected_oui = self.oui_combo.currentText()
        if not selected_oui:
            self.append_notification("[ smar: - ] error: No OUI selected.")
            return
        parts = selected_oui.split(":")
        if len(parts) != 3:
            self.append_notification("[ smar: - ] error: OUI format invalid. Should be XX:XX:XX.")
            return
        random_part = ":".join("{:02X}".format(random.randint(0,255)) for _ in range(3))
        smart_mac = selected_oui + ":" + random_part
        old_mac = get_current_mac_iface(iface)
        try:
            subprocess.run(["sudo", "-S", "ip", "link", "set", iface, "down"],
                           input=SUDO_PASSWORD+"\n", text=True, check=True)
            subprocess.run(["sudo", "-S", "ip", "link", "set", iface, "address", smart_mac],
                           input=SUDO_PASSWORD+"\n", text=True, check=True)
            subprocess.run(["sudo", "-S", "ip", "link", "set", iface, "up"],
                           input=SUDO_PASSWORD+"\n", text=True, check=True)
            self.append_notification(f"[ smar: + ] {iface}: {smart_mac}")
            logging.info(f"smar: MAC changed for {iface} to {smart_mac}")
            append_smart_change(iface, old_mac, smart_mac)
        except Exception as e:
            self.append_notification(f"[ smar: - ] error: {str(e)}")
    
    def resetToDefault(self):
        iface = self.iface_combo.currentText()
        if not iface:
            self.append_notification("[ smar: - ] error: No interface selected.")
            return
        if not SUDO_PASSWORD:
            self.append_notification("[ smar: - ] error: Sudo password not set. Please set it in the Sudo Password tab.")
            return
        default_mac = None
        if os.path.exists("default_mac_address.json"):
            with open("default_mac_address.json", "r") as f:
                try:
                    data = json.load(f)
                    default_mac = data.get(iface)
                except:
                    default_mac = None
        if not default_mac:
            self.append_notification(f"[ smar: - ] error: Default MAC not found for {iface}")
            return
        try:
            subprocess.run(["sudo", "-S", "ip", "link", "set", iface, "down"],
                           input=SUDO_PASSWORD+"\n", text=True, check=True)
            self.append_notification(f"[ smar: + ] Successfully brought down interface {iface}")
        except Exception as e:
            self.append_notification(f"[ smar: - ] error bringing down {iface}: {str(e)}")
            return
        try:
            subprocess.run(["sudo", "-S", "ip", "link", "set", iface, "address", default_mac],
                           input=SUDO_PASSWORD+"\n", text=True, check=True)
            self.append_notification(f"[ smar: + ] Successfully reset MAC for {iface}")
        except Exception as e:
            self.append_notification(f"[ smar: - ] error resetting MAC: {str(e)}")
            return
        try:
            subprocess.run(["sudo", "-S", "ip", "link", "set", iface, "up"],
                           input=SUDO_PASSWORD+"\n", text=True, check=True)
            self.append_notification(f"[ smar: + ] Interface {iface} is up")
        except Exception as e:
            self.append_notification(f"[ smar: - ] error bringing up interface {iface}: {str(e)}")
            return

    def displaySmartLog(self):
        dlg = LogDialog("mac_changer.log", filter_str="smar:", parent=self)
        dlg.exec()

    def displaySmartChanges(self):
        dlg = ChangesDialog(self.changes_file, title="Smart MAC Changes", parent=self)
        dlg.exec()

    def append_notification(self, message):
        self.notification_area.append(message)

#############################################
# Main Window
#############################################

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Kali Linux MAC Changer")
        self.resize(600, 550)
        self.initUI()
        # Capture original (default) MAC addresses at startup
        self.original_macs = {}
        for iface in get_interfaces():
            mac = get_current_mac_iface(iface)
            self.original_macs[iface] = mac
        # Save the original MAC addresses to default_mac_address.json
        with open("default_mac_address.json", "w") as f:
            json.dump(self.original_macs, f, indent=4)

    def initUI(self):
        tabs = QTabWidget()
        tabs.addTab(SudoPasswordTab(), "Sudo Password")
        tabs.addTab(ManualMACTab(), "Manual MAC")
        tabs.addTab(AutoMACTab(), "Auto MAC")
        tabs.addTab(SmartMACTab(), "Smart MAC")
        self.setCentralWidget(tabs)

    def closeEvent(self, event):
        # Check if any interface's current MAC differs from the original MAC.
        restore_needed = False
        for iface, orig_mac in self.original_macs.items():
            current_mac = get_current_mac_iface(iface)
            if current_mac != orig_mac:
                restore_needed = True
                break

        if restore_needed:
            reply = QMessageBox.question(
                self,
                "Restore Default MAC?",
                "Your current MAC address differs from the original hardware MAC.\n"
                "When you close the program, the MAC address will be restored to the default.\n"
                "Do you want to continue and restore the default MAC addresses?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.restore_default_macs()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()

    def restore_default_macs(self):
        # Restore original MAC addresses for all interfaces in original_macs
        for iface, orig_mac in self.original_macs.items():
            try:
                subprocess.run(["sudo", "-S", "ip", "link", "set", iface, "down"],
                               input=SUDO_PASSWORD+"\n", text=True, check=True)
                subprocess.run(["sudo", "-S", "ip", "link", "set", iface, "address", orig_mac],
                               input=SUDO_PASSWORD+"\n", text=True, check=True)
                subprocess.run(["sudo", "-S", "ip", "link", "set", iface, "up"],
                               input=SUDO_PASSWORD+"\n", text=True, check=True)
                logging.info(f"Restored default MAC for {iface} to {orig_mac}")
            except Exception as e:
                logging.error(f"Error restoring MAC for {iface}: {e}")
        QMessageBox.information(self, "MAC Restored", "Default MAC addresses have been restored.")

#############################################
# Main Application Entry Point
#############################################

def main():
    app = QApplication(sys.argv)
    dark_palette = QPalette()
    dark_palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
    dark_palette.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))
    dark_palette.setColor(QPalette.ColorRole.Base, QColor(25, 25, 25))
    dark_palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
    dark_palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(255, 255, 255))
    dark_palette.setColor(QPalette.ColorRole.ToolTipText, QColor(255, 255, 255))
    dark_palette.setColor(QPalette.ColorRole.Text, QColor(255, 255, 255))
    dark_palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
    dark_palette.setColor(QPalette.ColorRole.ButtonText, QColor(255, 255, 255))
    dark_palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
    dark_palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
    dark_palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
    dark_palette.setColor(QPalette.ColorRole.HighlightedText, QColor(0, 0, 0))
    app.setPalette(dark_palette)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
