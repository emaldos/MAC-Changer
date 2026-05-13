import sys
import os
import json
import logging
import random
import re
import time
from PyQt6.QtWidgets import QApplication,QMainWindow,QWidget,QTabWidget,QVBoxLayout,QHBoxLayout,QPushButton,QComboBox,QLineEdit,QTextEdit,QLabel,QMessageBox,QDialog,QTableWidget,QTableWidgetItem,QHeaderView,QScrollArea,QFrame,QGraphicsDropShadowEffect,QSizePolicy,QFileDialog,QCheckBox
from PyQt6.QtGui import QPalette,QColor,QRegularExpressionValidator,QIntValidator,QFont
from PyQt6.QtCore import QRegularExpression,QObject,pyqtSignal,QThread,Qt,QTimer
from mac_changer.mac_tools import check_environment,generate_random_mac,generate_vendor_mac,get_interfaces,get_current_mac_iface,get_interface_status,set_interface_down,set_interface_mac,set_interface_up,validate_sudo_password
from mac_changer.storage import AUTO_CHANGES_FILE,COMPANY_OUIS_FILE,DEFAULT_MAC_FILE,LOG_FILE,MANUAL_CHANGES_FILE,SMART_CHANGES_FILE,DEFAULT_SETTINGS,append_change,delete_mac_profile,ensure_runtime_files,export_changes,export_log,get_profiles_for_interface,load_default_macs,load_settings,save_mac_profile,save_settings,setup_logging
SUDO_PASSWORD=""
SUDO_VALID=False
APP_SETTINGS=load_settings()
INTERFACE_STATUS_REFRESH_MS=APP_SETTINGS["refresh_interval_seconds"]*1000
APP_STYLE="""
QMainWindow{background:#070b12;}
QWidget{font-family:"Segoe UI","Arial";font-size:13px;color:#e8eef8;}
QWidget#Page{background:transparent;}
QWidget#ContentPage{background:transparent;}
QWidget#LeftColumn,QWidget#RightColumn{background:transparent;}
QFrame#GlassPanel{background:rgba(18,26,40,214);border:1px solid rgba(148,163,184,48);border-radius:18px;}
QLabel{color:#e8eef8;}
QLabel#SectionTitle{font-size:16px;font-weight:700;color:#f6f8fc;}
QLabel#FieldLabel{font-size:12px;font-weight:600;color:#9fb0ca;}
QLabel#HintText{font-size:12px;color:#94a3b8;}
QLabel#Metric{background:rgba(59,130,246,35);border:1px solid rgba(96,165,250,80);border-radius:10px;padding:6px 10px;color:#cfe5ff;}
QLabel#StateText{font-size:12px;color:#9fb0ca;padding:0 2px;}
QLineEdit,QComboBox{min-height:34px;background:rgba(8,13,23,190);border:1px solid rgba(135,160,210,52);border-radius:10px;padding:5px 10px;color:#f8fafc;selection-background-color:#2563eb;}
QLineEdit:focus,QComboBox:focus,QTextEdit:focus{border:1px solid rgba(96,165,250,190);background:rgba(11,18,32,230);}
QComboBox::drop-down{border:0;width:30px;}
QComboBox QAbstractItemView{background:#0f172a;color:#e5eefb;border:1px solid #334155;selection-background-color:#2563eb;outline:0;}
QCheckBox{color:#dbeafe;font-weight:600;padding:6px 2px;}
QCheckBox::indicator{width:18px;height:18px;border-radius:5px;border:1px solid rgba(135,160,210,90);background:rgba(8,13,23,210);}
QCheckBox::indicator:checked{background:#2563eb;border:1px solid #93c5fd;}
QTextEdit{background:rgba(4,8,15,210);border:1px solid rgba(135,160,210,45);border-radius:14px;padding:10px;color:#dbeafe;font-family:"Cascadia Mono","Consolas";font-size:12px;}
QPushButton{min-height:30px;border-radius:10px;border:1px solid rgba(148,163,184,55);background:rgba(31,41,55,190);padding:4px 10px;color:#f8fafc;font-weight:600;}
QPushButton:hover{background:rgba(51,65,85,220);border-color:rgba(148,163,184,110);}
QPushButton:pressed{background:rgba(15,23,42,240);}
QPushButton[kind="primary"]{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #2563eb,stop:1 #14b8a6);border:1px solid rgba(125,211,252,150);}
QPushButton[kind="danger"]{background:rgba(127,29,29,190);border:1px solid rgba(248,113,113,110);}
QPushButton[kind="ghost"]{background:rgba(15,23,42,135);}
QTabWidget::pane{border:0;background:transparent;}
QTabWidget::tab-bar{alignment:center;}
QTabBar::tab{background:rgba(15,23,42,145);border:1px solid rgba(148,163,184,42);border-radius:12px;padding:10px 18px;margin-right:8px;color:#94a3b8;min-width:92px;}
QTabBar::tab:selected{background:rgba(37,99,235,95);color:#ffffff;border-color:rgba(96,165,250,160);}
QTabBar::tab:hover{background:rgba(30,41,59,220);color:#dbeafe;}
QTableWidget{background:rgba(4,8,15,210);border:1px solid rgba(135,160,210,45);border-radius:12px;gridline-color:rgba(148,163,184,42);color:#e8eef8;selection-background-color:#2563eb;}
QHeaderView::section{background:rgba(15,23,42,230);color:#cbd5e1;border:0;padding:8px;font-weight:600;}
QScrollArea{border:0;background:transparent;}
QScrollArea>QWidget>QWidget{background:transparent;}
QScrollBar:vertical{background:rgba(15,23,42,130);width:10px;margin:2px;border-radius:5px;}
QScrollBar::handle:vertical{background:rgba(96,165,250,120);border-radius:5px;min-height:40px;}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0;}
QScrollBar:horizontal{background:rgba(15,23,42,130);height:10px;margin:2px;border-radius:5px;}
QScrollBar::handle:horizontal{background:rgba(96,165,250,120);border-radius:5px;min-width:40px;}
QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal{width:0;}
QDialog,QMessageBox{background:#0b1120;color:#e5eefb;}
"""
THEME_LABELS={"dark_glass":"Dark Glass","dark_compact":"Dark Compact","high_contrast":"High Contrast"}
THEME_KEYS={value:key for key,value in THEME_LABELS.items()}
def get_app_style(theme=None):
    theme=theme or APP_SETTINGS.get("theme","dark_glass")
    if theme=="dark_compact":
        return APP_STYLE+"QFrame#GlassPanel{border-radius:12px;}QPushButton{border-radius:8px;padding:3px 8px;}QLineEdit,QComboBox{border-radius:8px;min-height:32px;}QTextEdit{border-radius:10px;padding:8px;}QTabBar::tab{border-radius:10px;padding:8px 16px;}"
    if theme=="high_contrast":
        return APP_STYLE+"QMainWindow{background:#000000;}QFrame#GlassPanel{background:#07111f;border:1px solid #93c5fd;}QLabel#Metric{background:#0b2447;border:1px solid #60a5fa;color:#ffffff;}QPushButton{background:#111827;border:1px solid #dbeafe;color:#ffffff;}QPushButton[kind=\"primary\"]{background:#005fcc;border:1px solid #bfdbfe;}QPushButton[kind=\"danger\"]{background:#7f1d1d;border:1px solid #fecaca;}QTextEdit,QLineEdit,QComboBox{border:1px solid #93c5fd;}"
    return APP_STYLE
def apply_app_settings(settings):
    global APP_SETTINGS,INTERFACE_STATUS_REFRESH_MS
    APP_SETTINGS=settings.copy()
    INTERFACE_STATUS_REFRESH_MS=APP_SETTINGS["refresh_interval_seconds"]*1000
    app=QApplication.instance()
    if app:
        app.setStyleSheet(get_app_style())
def add_shadow(widget,blur=30,opacity=120):
    effect=QGraphicsDropShadowEffect(widget)
    effect.setBlurRadius(blur)
    effect.setOffset(0,12)
    effect.setColor(QColor(0,0,0,opacity))
    widget.setGraphicsEffect(effect)
def make_page(parent):
    parent.setObjectName("Page")
    layout=QVBoxLayout()
    layout.setContentsMargins(24,24,24,24)
    layout.setSpacing(16)
    parent.setLayout(layout)
    return layout
def make_two_column_page(parent):
    parent.setObjectName("Page")
    outer=QVBoxLayout(parent)
    outer.setContentsMargins(0,0,0,0)
    outer.setSpacing(0)
    scroll=QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setAlignment(Qt.AlignmentFlag.AlignCenter)
    scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    content=QWidget()
    content.setObjectName("ContentPage")
    layout=QHBoxLayout(content)
    layout.setContentsMargins(16,12,16,12)
    layout.setSpacing(14)
    left=QWidget()
    left.setObjectName("LeftColumn")
    left.setMinimumWidth(340)
    left.setSizePolicy(QSizePolicy.Policy.Expanding,QSizePolicy.Policy.Preferred)
    left_layout=QVBoxLayout(left)
    left_layout.setContentsMargins(0,0,0,0)
    left_layout.setSpacing(10)
    right=QWidget()
    right.setObjectName("RightColumn")
    right.setMinimumWidth(340)
    right.setSizePolicy(QSizePolicy.Policy.Expanding,QSizePolicy.Policy.Preferred)
    right_layout=QVBoxLayout(right)
    right_layout.setContentsMargins(0,0,0,0)
    right_layout.setSpacing(10)
    layout.addWidget(left,1)
    layout.addWidget(right,1)
    scroll.setWidget(content)
    outer.addWidget(scroll)
    return left_layout,right_layout
def make_panel(title=None,subtitle=None):
    panel=QFrame()
    panel.setObjectName("GlassPanel")
    add_shadow(panel)
    layout=QVBoxLayout(panel)
    layout.setContentsMargins(16,12,16,14)
    layout.setSpacing(8)
    if title:
        label=QLabel(title)
        label.setObjectName("SectionTitle")
        layout.addWidget(label)
    if subtitle:
        hint=QLabel(subtitle)
        hint.setWordWrap(True)
        hint.setObjectName("HintText")
        layout.addWidget(hint)
    return panel,layout
def make_field_widget(label_text,widget):
    holder=QWidget()
    layout=QVBoxLayout(holder)
    layout.setContentsMargins(0,0,0,0)
    layout.setSpacing(4)
    label=QLabel(label_text)
    label.setObjectName("FieldLabel")
    layout.addWidget(label)
    widget.setSizePolicy(QSizePolicy.Policy.Expanding,QSizePolicy.Policy.Fixed)
    layout.addWidget(widget)
    holder.setSizePolicy(QSizePolicy.Policy.Expanding,QSizePolicy.Policy.Fixed)
    return holder
def add_field(layout,label_text,widget):
    layout.addWidget(make_field_widget(label_text,widget))
def style_button(button,kind="ghost"):
    button.setProperty("kind",kind)
    button.setMinimumHeight(30)
    button.style().unpolish(button)
    button.style().polish(button)
    return button
def make_action_row(*buttons):
    row=QHBoxLayout()
    row.setSpacing(8)
    for button in buttons:
        button.setMinimumWidth(122)
        button.setSizePolicy(QSizePolicy.Policy.Expanding,QSizePolicy.Policy.Fixed)
        row.addWidget(button)
    return row
def make_compact_action_row(*buttons):
    row=QHBoxLayout()
    row.setSpacing(8)
    for button in buttons:
        button.setMinimumWidth(82)
        button.setSizePolicy(QSizePolicy.Policy.Expanding,QSizePolicy.Policy.Fixed)
        row.addWidget(button)
    return row
def make_hint(text):
    label=QLabel(text)
    label.setWordWrap(True)
    label.setObjectName("HintText")
    return label
def setup_console(area,minimum=160,maximum=None):
    area.setReadOnly(True)
    area.setMinimumHeight(minimum)
    if maximum:
        area.setMaximumHeight(maximum)
    area.setObjectName("Console")
def add_console_panel(page,title="Notifications"):
    panel,body=make_panel(title)
    area=QTextEdit()
    setup_console(area)
    body.addWidget(area)
    page.addWidget(panel,1)
    return area
def make_console_panel(title="Notifications",minimum=190,maximum=220):
    panel,body=make_panel(title)
    area=QTextEdit()
    setup_console(area,minimum,maximum)
    body.addWidget(area,1)
    return panel,area
def make_metric_panel(title="Interface Status",text="Current MAC: N/A"):
    panel,body=make_panel(title)
    metric=QLabel(text)
    metric.setObjectName("Metric")
    metric.setWordWrap(True)
    body.addWidget(metric)
    return panel,metric
def add_action_state(panel,text="State: Ready"):
    label=QLabel(text)
    label.setObjectName("StateText")
    panel.layout().addWidget(label)
    return label
def pump_ui():
    app=QApplication.instance()
    if app:
        app.processEvents()
def set_tab_busy(owner,busy,state="Ready",active_button=None,active_text=None):
    buttons=[button for button in getattr(owner,"busy_buttons",[]) if button]
    if busy:
        owner._busy=True
        owner._busy_original_texts={button:button.text() for button in buttons}
        for button in buttons:
            button.setEnabled(False)
        if active_button and active_text:
            active_button.setText(active_text)
        if hasattr(owner,"action_state_label"):
            owner.action_state_label.setText(f"State: {state}")
        pump_ui()
        return
    for button,text in getattr(owner,"_busy_original_texts",{}).items():
        button.setText(text)
    owner._busy=False
    if hasattr(owner,"action_state_label"):
        owner.action_state_label.setText("State: Ready")
    if hasattr(owner,"refresh_current_mac"):
        owner.refresh_current_mac()
    pump_ui()
def populate_interfaces(combo,preferred=None,owner=None):
    current=preferred or combo.currentText()
    if owner:
        owner._interface_load_error=""
    ok,message=check_environment(False)
    if not ok:
        combo.blockSignals(True)
        combo.clear()
        combo.blockSignals(False)
        if owner:
            owner._interface_load_error=message
        return []
    interfaces=get_interfaces()
    combo.blockSignals(True)
    combo.clear()
    combo.addItems(interfaces)
    if current in interfaces:
        combo.setCurrentText(current)
    combo.blockSignals(False)
    return interfaces
def save_default_for_interfaces(interfaces):
    data={}
    if os.path.exists(DEFAULT_MAC_FILE):
        with open(DEFAULT_MAC_FILE,"r") as f:
            try:
                data=json.load(f)
            except:
                data={}
    changed=False
    for iface in interfaces:
        if iface not in data:
            mac=get_current_mac_iface(iface)
            if mac!="00:00:00:00:00:00":
                data[iface]=mac
                changed=True
    if changed:
        with open(DEFAULT_MAC_FILE,"w") as f:
            json.dump(data,f,indent=4)
def attach_status_timer(owner):
    owner.status_timer=QTimer(owner)
    owner.status_timer.setInterval(INTERFACE_STATUS_REFRESH_MS)
    owner.status_timer.timeout.connect(owner.refresh_current_mac)
    owner.status_timer.start()
def set_buttons_enabled(buttons,enabled):
    for button in buttons:
        button.setEnabled(enabled)
def update_live_interface_state(owner,buttons,message_prefix="[ - ]"):
    iface=owner.iface_combo.currentText()
    busy=getattr(owner,"_busy",False)
    if not iface:
        owner.current_mac_label.setText("Current MAC: N/A")
        if not busy:
            set_buttons_enabled(buttons,False)
        owner._interface_available=False
        return
    available,mac=get_interface_status(iface)
    if available:
        owner.current_mac_label.setText(f"Current MAC: {mac}")
        if not busy:
            set_buttons_enabled(buttons,True)
        if not getattr(owner,"_suppress_live_notice",False) and getattr(owner,"_interface_available",None) is False:
            owner.append_notification(f"{message_prefix.replace('-', '+')} Interface {iface} is available again.")
    else:
        owner.current_mac_label.setText("Current MAC: unavailable")
        if not busy:
            set_buttons_enabled(buttons,False)
        if not getattr(owner,"_suppress_live_notice",False) and getattr(owner,"_interface_available",None) is True:
            owner.append_notification(f"{message_prefix} Interface {iface} is no longer available. Refresh interfaces.")
    owner._interface_available=available
def restore_all_default_macs(owner,message_prefix="[ - ]"):
    if not sudo_is_ready(owner,message_prefix):
        return
    defaults=load_default_macs()
    if not defaults:
        owner.append_notification(f"{message_prefix} No saved default MAC addresses found.")
        return
    reply=QMessageBox.question(owner,"Restore All Defaults","Restore all saved interfaces to their default MAC addresses?",QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No)
    if reply!=QMessageBox.StandardButton.Yes:
        return
    restored=0
    failed=[]
    set_tab_busy(owner,True,"Restoring all defaults",getattr(owner,"restore_all_btn",None),"Restoring...")
    try:
        for iface,mac in defaults.items():
            try:
                set_interface_down(iface,SUDO_PASSWORD)
                set_interface_mac(iface,SUDO_PASSWORD,mac)
                set_interface_up(iface,SUDO_PASSWORD)
                restored+=1
                owner.append_notification(f"{message_prefix.replace('-', '+')} Restored {iface} to {mac}")
                logging.info(f"Restored default MAC for {iface} to {mac}")
            except Exception as error:
                failed.append(iface)
                owner.append_notification(f"{message_prefix} Failed to restore {iface}: {error}")
                logging.error(f"Error restoring MAC for {iface}: {error}")
        owner.append_notification(f"{message_prefix.replace('-', '+')} Restore all complete. Restored: {restored}, Failed: {len(failed)}")
    finally:
        set_tab_busy(owner,False)
def is_valid_unicast_mac(mac):
    if not re.match(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$",mac):
        return False
    try:
        parts=mac.split(":")
        return not all(part=="00" for part in parts) and int(parts[0],16)%2==0
    except Exception:
        return False
def sudo_is_ready(owner,message_prefix="[ - ]"):
    if SUDO_VALID and SUDO_PASSWORD:
        return True
    owner.append_notification(f"{message_prefix} error: Validate sudo password in the Access tab before running this action.")
    return False
def choose_export_path(owner,title,default_name):
    path,selected_filter=QFileDialog.getSaveFileName(owner,title,default_name,"JSON Files (*.json);;Text Files (*.txt)")
    if not path:
        return ""
    suffix=os.path.splitext(path)[1].lower()
    if suffix not in [".json",".txt"]:
        path += ".txt" if "Text" in selected_filter else ".json"
    return path
def export_changes_from_ui(owner,source_path,title,default_name,message_prefix="[ + ]",error_prefix="[ - ]"):
    path=choose_export_path(owner,title,default_name)
    if not path:
        return
    try:
        count=export_changes(source_path,path)
        if count:
            owner.append_notification(f"{message_prefix} Exported {count} change records to {path}")
        else:
            owner.append_notification(f"{error_prefix} No records to export.")
    except Exception as error:
        owner.append_notification(f"{error_prefix} export failed: {error}")
class LogDialog(QDialog):
    def __init__(self, file_path, filter_str=None, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self.filter_str = filter_str
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
        self.export_btn = QPushButton("Export")
        self.close_btn = QPushButton("Close")
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addWidget(self.export_btn)
        btn_layout.addWidget(self.close_btn)
        layout.addLayout(btn_layout)
        self.setLayout(layout)
        self.clear_btn.clicked.connect(self.clearLog)
        self.export_btn.clicked.connect(self.exportLog)
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
    def exportLog(self):
        path=choose_export_path(self,"Export Log","mac_changer_log.txt")
        if not path:
            return
        try:
            count=export_log(self.file_path,path,self.filter_str)
            if count:
                QMessageBox.information(self,"Export Complete",f"Exported {count} log lines.")
            else:
                QMessageBox.warning(self,"No Records","No log records to export.")
        except Exception as error:
            QMessageBox.warning(self,"Export Failed",str(error))
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
        self.export_btn = QPushButton("Export")
        self.close_btn = QPushButton("Close")
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addWidget(self.export_btn)
        btn_layout.addWidget(self.close_btn)
        layout.addLayout(btn_layout)
        self.setLayout(layout)
        self.clear_btn.clicked.connect(self.clearChanges)
        self.export_btn.clicked.connect(self.exportChanges)
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
    def exportChanges(self):
        path=choose_export_path(self,"Export Changes","mac_changes.json")
        if not path:
            return
        try:
            count=export_changes(self.file_path,path)
            if count:
                QMessageBox.information(self,"Export Complete",f"Exported {count} change records.")
            else:
                QMessageBox.warning(self,"No Records","No records to export.")
        except Exception as error:
            QMessageBox.warning(self,"Export Failed",str(error))
class EditCompanyDialog(QDialog):
    def __init__(self, company_name="", ouis=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add/Edit Company")
        self.company_name = company_name
        self.ouis = ouis if ouis is not None else []
        self.initUI()
    def initUI(self):
        layout = QVBoxLayout()
        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("Company Name:"))
        self.name_edit = QLineEdit(self.company_name)
        name_layout.addWidget(self.name_edit)
        layout.addLayout(name_layout)
        self.resize(600, 400)
        layout.addWidget(QLabel("MAC Prefixes (OUIs) - Format: XX:XX:XX:"))
        self.oui_container = QVBoxLayout()
        for oui in self.ouis:
            self.addOUIRow(oui)
        container_widget = QWidget()
        container_widget.setLayout(self.oui_container)
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(container_widget)
        layout.addWidget(scroll_area)
        new_layout = QHBoxLayout()
        self.new_oui_edit = QLineEdit()
        self.new_oui_edit.setPlaceholderText("Enter new OUI (e.g., 001122)")
        self.new_oui_edit.setMaxLength(8)
        regex = QRegularExpression(r"^([0-9A-Fa-f]{2}:){0,2}[0-9A-Fa-f]{0,2}$")
        validator = QRegularExpressionValidator(regex)
        self.new_oui_edit.setValidator(validator)
        self.new_oui_edit.textChanged.connect(self.autoFormatNewOUI)
        new_layout.addWidget(self.new_oui_edit)
        self.add_oui_btn = QPushButton("Add OUI")
        new_layout.addWidget(self.add_oui_btn)
        self.add_oui_btn.clicked.connect(self.handleAddOUI)
        layout.addLayout(new_layout)
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
        raw = re.sub(r"[^0-9A-Fa-f]", "", text)[:6]
        formatted = ":".join(raw[i:i+2] for i in range(0, len(raw), 2))
        if formatted != text:
            cursor_pos = self.new_oui_edit.cursorPosition()
            self.new_oui_edit.blockSignals(True)
            self.new_oui_edit.setText(formatted)
            self.new_oui_edit.setCursorPosition(len(formatted))
            self.new_oui_edit.blockSignals(False)
    def addOUIRow(self, oui):
        row = QHBoxLayout()
        label = QLabel(oui)
        row.addWidget(label)
        del_btn = QPushButton("X")
        del_btn.setFixedWidth(30)
        del_btn.clicked.connect(lambda: self.removeOUIRow(row))
        row.addWidget(del_btn)
        self.oui_container.addLayout(row)
    def removeOUIRow(self, row_layout):
        for i in reversed(range(row_layout.count())):
            widget = row_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)
        self.oui_container.removeItem(row_layout)
    def handleAddOUI(self):
        text = self.new_oui_edit.text().strip()
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
        self.companies = companies
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
        with open(COMPANY_OUIS_FILE, "w") as f:
            json.dump(self.companies, f, indent=4)
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
        return generate_random_mac()
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
                set_interface_down(self.iface, self.sudo_password)
                set_interface_mac(self.iface, self.sudo_password, new_mac)
                set_interface_up(self.iface, self.sudo_password)
                log_msg = f"[ + ] {self.iface}: {new_mac}"
                self.update_notification.emit(log_msg)
                logging.info(f"auto: MAC changed for {self.iface} to {new_mac}")
                append_change(AUTO_CHANGES_FILE,self.iface, old_mac, new_mac)
            except Exception as e:
                self.error_signal.emit(f"[ - ] error: {str(e)}")
                break
            time.sleep(delay)
        self.finished.emit()
class SudoPasswordTab(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
    def initUI(self):
        left,right=make_two_column_page(self)
        panel,body=make_panel("Session Access","Password is kept only for the current app session.")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Sudo password")
        add_field(body,"Sudo Password",self.password_input)
        self.set_password_btn = style_button(QPushButton("Validate Password"),"primary")
        body.addLayout(make_action_row(self.set_password_btn))
        left.addWidget(panel)
        left.addStretch(1)
        self.set_password_btn.clicked.connect(self.validate_password)
        self.password_input.textChanged.connect(self.clear_validation_state)
        status_panel,status_body=make_panel("Access State","Validate sudo before using Manual, Auto, or Smart actions.")
        self.status_label=QLabel("Sudo: not validated")
        self.status_label.setObjectName("Metric")
        status_body.addWidget(self.status_label)
        right.addWidget(status_panel)
        console_panel,self.notification_area=make_console_panel("Session Status",180,210)
        right.addWidget(console_panel,1)
    def clear_validation_state(self):
        global SUDO_PASSWORD,SUDO_VALID
        if SUDO_PASSWORD or SUDO_VALID:
            SUDO_PASSWORD=""
            SUDO_VALID=False
            self.status_label.setText("Sudo: not validated")
    def validate_password(self):
        global SUDO_PASSWORD,SUDO_VALID
        pwd = self.password_input.text().strip()
        valid,message=validate_sudo_password(pwd)
        if valid:
            SUDO_PASSWORD=pwd
            SUDO_VALID=True
            self.status_label.setText("Sudo: validated")
            self.notification_area.append(f"[ + ] {message}")
        else:
            SUDO_PASSWORD=""
            SUDO_VALID=False
            self.status_label.setText("Sudo: validation failed")
            self.notification_area.append(f"[ - ] {message}")
class ManualMACTab(QWidget):
    def __init__(self):
        super().__init__()
        self.default_mac_file = DEFAULT_MAC_FILE
        self.changes_file = MANUAL_CHANGES_FILE
        self.log_file = LOG_FILE
        self.initUI()
        self.setup_logging()
    def initUI(self):
        left,right=make_two_column_page(self)
        panel,body=make_panel("Manual MAC Change")
        self.iface_combo = QComboBox()
        add_field(body,"Network Interface",self.iface_combo)
        self.refresh_interfaces_btn = style_button(QPushButton("Refresh Interfaces"),"ghost")
        self.mac_entry = QLineEdit()
        self.mac_entry.setMaxLength(17)
        self.mac_entry.setPlaceholderText("00:11:22:AA:BB:CC")
        regex = QRegularExpression(r"^[0-9A-Fa-f:]{0,17}$")
        validator = QRegularExpressionValidator(regex)
        self.mac_entry.setValidator(validator)
        self.mac_entry.textChanged.connect(self.auto_format_mac)
        add_field(body,"New MAC Address",self.mac_entry)
        profile_row=QHBoxLayout()
        profile_row.setSpacing(8)
        self.profile_name_entry=QLineEdit()
        self.profile_name_entry.setPlaceholderText("Profile name")
        self.profile_combo=QComboBox()
        profile_row.addWidget(self.profile_name_entry)
        profile_row.addWidget(self.profile_combo)
        body.addLayout(profile_row)
        self.save_profile_btn=style_button(QPushButton("Save"),"ghost")
        self.apply_profile_btn=style_button(QPushButton("Load"),"primary")
        self.delete_profile_btn=style_button(QPushButton("Delete"),"danger")
        body.addLayout(make_compact_action_row(self.save_profile_btn,self.apply_profile_btn,self.delete_profile_btn))
        info_button = style_button(QPushButton("MAC Address Info"),"ghost")
        info_button.clicked.connect(self.show_mac_info)
        self.change_btn = style_button(QPushButton("Apply MAC"),"primary")
        self.reset_btn = style_button(QPushButton("Reset Default"),"danger")
        body.addLayout(make_action_row(self.change_btn,self.reset_btn))
        body.addLayout(make_action_row(info_button,self.refresh_interfaces_btn))
        left.addWidget(panel)
        left.addStretch(1)
        status_panel,self.current_mac_label=make_metric_panel("Interface Status")
        right.addWidget(status_panel)
        console_panel,self.notification_area=make_console_panel("Notifications",108,128)
        self.display_log_btn = style_button(QPushButton("Display Log"),"ghost")
        self.display_changes_btn = style_button(QPushButton("Display Changes"),"ghost")
        self.export_changes_btn = style_button(QPushButton("Export Changes"),"ghost")
        self.restore_all_btn = style_button(QPushButton("Restore All Defaults"),"danger")
        console_panel.layout().addLayout(make_action_row(self.display_log_btn,self.display_changes_btn))
        console_panel.layout().addLayout(make_action_row(self.export_changes_btn,self.restore_all_btn))
        right.addWidget(console_panel,1)
        self.action_state_label=add_action_state(status_panel)
        self.busy_buttons=[self.change_btn,self.reset_btn,self.refresh_interfaces_btn,self.restore_all_btn]
        self.iface_combo.currentTextChanged.connect(self.handle_interface_changed)
        self.refresh_interfaces_btn.clicked.connect(self.reload_interfaces)
        self.reload_interfaces()
        attach_status_timer(self)
        self.change_btn.clicked.connect(self.start_changing)
        self.reset_btn.clicked.connect(self.reset_to_default)
        self.save_profile_btn.clicked.connect(self.save_current_profile)
        self.apply_profile_btn.clicked.connect(self.apply_selected_profile)
        self.delete_profile_btn.clicked.connect(self.delete_selected_profile)
        self.display_log_btn.clicked.connect(self.display_log)
        self.display_changes_btn.clicked.connect(self.display_changes)
        self.export_changes_btn.clicked.connect(self.export_manual_changes)
        self.restore_all_btn.clicked.connect(self.restore_all_defaults)
    def refresh_current_mac(self):
        update_live_interface_state(self,[self.change_btn,self.reset_btn])
    def handle_interface_changed(self):
        self.refresh_current_mac()
        self.load_profiles_for_interface()
    def reload_interfaces(self):
        interfaces=populate_interfaces(self.iface_combo,owner=self)
        save_default_for_interfaces(interfaces)
        has_interfaces=bool(interfaces)
        self.change_btn.setEnabled(has_interfaces)
        self.reset_btn.setEnabled(has_interfaces)
        self._suppress_live_notice=True
        self.refresh_current_mac()
        self._suppress_live_notice=False
        self.load_profiles_for_interface()
        if has_interfaces:
            self.append_notification(f"[ + ] Interfaces loaded: {', '.join(interfaces)}")
        elif getattr(self,"_interface_load_error",""):
            self.append_notification(f"[ - ] {self._interface_load_error}")
        else:
            self.append_notification("[ - ] No network interfaces found.")
    def load_profiles_for_interface(self):
        iface=self.iface_combo.currentText()
        profiles=get_profiles_for_interface(iface) if iface else {}
        current=self.profile_combo.currentText()
        self.profile_combo.blockSignals(True)
        self.profile_combo.clear()
        self.profile_combo.addItems(sorted(profiles.keys()))
        if current in profiles:
            self.profile_combo.setCurrentText(current)
        self.profile_combo.blockSignals(False)
        has_profiles=bool(profiles)
        self.apply_profile_btn.setEnabled(has_profiles)
        self.delete_profile_btn.setEnabled(has_profiles)
    def save_current_profile(self):
        iface=self.iface_combo.currentText()
        name=self.profile_name_entry.text().strip()
        mac=self.mac_entry.text().strip()
        if not iface:
            self.append_notification("[ - ] error: No interface selected.")
            return
        if not name:
            self.append_notification("[ - ] error: Enter a profile name.")
            return
        if not is_valid_unicast_mac(mac):
            self.append_notification("[ - ] error: Enter a valid unicast MAC before saving.")
            return
        profiles=get_profiles_for_interface(iface)
        if name in profiles:
            reply=QMessageBox.question(self,"Overwrite Profile",f"Overwrite profile {name} for {iface}?",QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No)
            if reply!=QMessageBox.StandardButton.Yes:
                return
        save_mac_profile(iface,name,mac)
        self.load_profiles_for_interface()
        self.profile_combo.setCurrentText(name)
        self.append_notification(f"[ + ] Profile saved for {iface}: {name} -> {mac}")
    def apply_selected_profile(self):
        iface=self.iface_combo.currentText()
        name=self.profile_combo.currentText()
        profiles=get_profiles_for_interface(iface) if iface else {}
        mac=profiles.get(name)
        if not mac:
            self.append_notification("[ - ] error: No profile selected.")
            return
        self.mac_entry.setText(mac)
        self.append_notification(f"[ + ] Profile loaded: {name} -> {mac}")
    def delete_selected_profile(self):
        iface=self.iface_combo.currentText()
        name=self.profile_combo.currentText()
        if not iface or not name:
            self.append_notification("[ - ] error: No profile selected.")
            return
        reply=QMessageBox.question(self,"Delete Profile",f"Delete profile {name} for {iface}?",QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No)
        if reply!=QMessageBox.StandardButton.Yes:
            return
        delete_mac_profile(iface,name)
        self.load_profiles_for_interface()
        self.append_notification(f"[ + ] Profile deleted: {name}")
    def restore_all_defaults(self):
        restore_all_default_macs(self)
    def setup_logging(self):
        logging.basicConfig(
            filename=str(self.log_file),
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
        if not iface:
            self.append_notification("[ - ] error: No interface selected.")
            return
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
        if not sudo_is_ready(self):
            return
        set_tab_busy(self,True,"Applying MAC",self.change_btn,"Applying...")
        try:
            default_mac = self.get_current_mac(iface)
            if not self.is_default_saved(iface) and default_mac != "00:00:00:00:00:00":
                self.save_default_mac(iface, default_mac)
            try:
                set_interface_down(iface, SUDO_PASSWORD)
                self.append_notification(f"[ + ] Successfully brought down interface {iface}")
                logging.info(f"Interface {iface} brought down")
            except Exception as e:
                err = str(e)
                self.append_notification(f"[ - ] error while bringing down {iface}: {err}")
                logging.error(f"Error bringing down interface {iface}: {err}")
                return
            try:
                set_interface_mac(iface, SUDO_PASSWORD, new_mac)
                self.append_notification(f"[ + ] Successfully changed MAC for {iface}")
                logging.info(f"MAC changed for {iface} to {new_mac}")
            except Exception as e:
                err = str(e)
                self.append_notification(f"[ - ] error changing MAC: {err}")
                logging.error(f"Error changing MAC for {iface}: {err}")
                self.append_notification("[ - ] Attempting to restore default MAC address...")
                self.reset_to_default(True)
                return
            try:
                set_interface_up(iface, SUDO_PASSWORD)
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
        finally:
            set_tab_busy(self,False)
    def reset_to_default(self,managed=False):
        iface = self.iface_combo.currentText()
        if not iface:
            self.append_notification("[ - ] error: No interface selected.")
            return
        if not sudo_is_ready(self):
            return
        default_mac = self.get_default_mac(iface)
        if not default_mac:
            self.append_notification(f"[ - ] error: Default MAC not found for {iface}")
            return
        if not managed:
            set_tab_busy(self,True,"Restoring default",self.reset_btn,"Restoring...")
        try:
            try:
                set_interface_down(iface, SUDO_PASSWORD)
                self.append_notification(f"[ + ] Successfully brought down interface {iface}")
                logging.info(f"Interface {iface} brought down for reset")
            except Exception as e:
                err = str(e)
                self.append_notification(f"[ - ] error while bringing down {iface} for reset: {err}")
                logging.error(f"Error bringing down interface {iface} for reset: {err}")
                return
            try:
                set_interface_mac(iface, SUDO_PASSWORD, default_mac)
                self.append_notification(f"[ + ] Successfully reset MAC for {iface}")
                logging.info(f"MAC reset for {iface} to {default_mac}")
            except Exception as e:
                err = str(e)
                self.append_notification(f"[ - ] error resetting MAC: {err}")
                logging.error(f"Error resetting MAC for {iface}: {err}")
                return
            try:
                set_interface_up(iface, SUDO_PASSWORD)
                self.append_notification(f"[ + ] Interface {iface} is up")
                logging.info(f"Interface {iface} brought up after reset")
            except Exception as e:
                err = str(e)
                self.append_notification(f"[ - ] error bringing up interface {iface} after reset: {err}")
                logging.error(f"Error bringing up interface {iface} after reset: {err}")
                return
        finally:
            if not managed:
                set_tab_busy(self,False)
    def get_current_mac(self, iface):
        return get_current_mac_iface(iface)
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
    def export_manual_changes(self):
        export_changes_from_ui(self,self.changes_file,"Export Manual Changes","manual_changes.json")
class AutoMACTab(QWidget):
    def __init__(self):
        super().__init__()
        self.thread = None
        self.worker = None
        self.initUI()
    def initUI(self):
        left,right=make_two_column_page(self)
        panel,body=make_panel("Automatic MAC Rotation","Generate random unicast MAC addresses for the selected interface.")
        self.iface_combo = QComboBox()
        add_field(body,"Network Interface",self.iface_combo)
        self.refresh_interfaces_btn = style_button(QPushButton("Refresh Interfaces"),"ghost")
        self.single_change_btn = style_button(QPushButton("Random Change"),"primary")
        body.addLayout(make_action_row(self.single_change_btn,self.refresh_interfaces_btn))
        schedule_layout = QHBoxLayout()
        schedule_layout.setSpacing(10)
        self.changes_edit = QLineEdit()
        self.changes_edit.setPlaceholderText("10")
        self.changes_edit.setValidator(QIntValidator(1, 1000000))
        schedule_layout.addWidget(make_field_widget("Total Changes",self.changes_edit))
        self.duration_edit = QLineEdit()
        self.duration_edit.setPlaceholderText("30")
        self.duration_edit.setValidator(QIntValidator(1, 1000000))
        schedule_layout.addWidget(make_field_widget("Duration Seconds",self.duration_edit))
        body.addLayout(schedule_layout)
        body.addWidget(make_hint("Keep delay at 0.05 seconds or higher for safer rotation speed."))
        self.flood_attack_btn = style_button(QPushButton("Start Schedule"),"primary")
        self.reset_default_btn = style_button(QPushButton("Reset Default"),"danger")
        body.addLayout(make_action_row(self.flood_attack_btn,self.reset_default_btn))
        left.addWidget(panel)
        left.addStretch(1)
        status_panel,self.current_mac_label=make_metric_panel("Interface Status")
        right.addWidget(status_panel)
        console_panel,self.notification_area=make_console_panel("Auto Notifications",125,145)
        self.display_auto_log_btn = style_button(QPushButton("Display Auto Log"),"ghost")
        self.display_auto_changes_btn = style_button(QPushButton("Display Auto Changes"),"ghost")
        self.export_auto_changes_btn = style_button(QPushButton("Export Changes"),"ghost")
        self.restore_all_btn = style_button(QPushButton("Restore All Defaults"),"danger")
        console_panel.layout().addLayout(make_action_row(self.display_auto_log_btn,self.display_auto_changes_btn))
        console_panel.layout().addLayout(make_action_row(self.export_auto_changes_btn,self.restore_all_btn))
        right.addWidget(console_panel,1)
        self.action_state_label=add_action_state(status_panel)
        self.busy_buttons=[self.single_change_btn,self.flood_attack_btn,self.reset_default_btn,self.refresh_interfaces_btn,self.restore_all_btn]
        self.iface_combo.currentTextChanged.connect(self.refresh_current_mac)
        self.refresh_interfaces_btn.clicked.connect(self.reload_interfaces)
        self.reload_interfaces()
        attach_status_timer(self)
        self.single_change_btn.clicked.connect(self.start_single_change)
        self.flood_attack_btn.clicked.connect(self.start_flooding_attack)
        self.reset_default_btn.clicked.connect(self.reset_default_mac)
        self.display_auto_log_btn.clicked.connect(self.display_auto_log)
        self.display_auto_changes_btn.clicked.connect(self.display_auto_changes)
        self.export_auto_changes_btn.clicked.connect(self.export_auto_changes)
        self.restore_all_btn.clicked.connect(self.restore_all_defaults)
    def refresh_current_mac(self):
        update_live_interface_state(self,[self.single_change_btn,self.flood_attack_btn,self.reset_default_btn])
    def reload_interfaces(self):
        interfaces=populate_interfaces(self.iface_combo,owner=self)
        save_default_for_interfaces(interfaces)
        has_interfaces=bool(interfaces)
        self.single_change_btn.setEnabled(has_interfaces)
        self.flood_attack_btn.setEnabled(has_interfaces)
        self.reset_default_btn.setEnabled(has_interfaces)
        self._suppress_live_notice=True
        self.refresh_current_mac()
        self._suppress_live_notice=False
        if has_interfaces:
            self.append_notification(f"[ + ] Interfaces loaded: {', '.join(interfaces)}")
        elif getattr(self,"_interface_load_error",""):
            self.append_notification(f"[ - ] {self._interface_load_error}")
        else:
            self.append_notification("[ - ] No network interfaces found.")
    def restore_all_defaults(self):
        restore_all_default_macs(self)
    def append_notification(self, message):
        self.notification_area.append(message)
    def start_single_change(self):
        iface = self.iface_combo.currentText()
        if not iface:
            self.append_notification("[ - ] error: No interface selected.")
            return
        if not sudo_is_ready(self):
            return
        set_tab_busy(self,True,"Changing MAC",self.single_change_btn,"Changing...")
        try:
            old_mac = get_current_mac_iface(iface)
            new_mac = AutoMACWorker(iface, 1, 1, SUDO_PASSWORD).generate_random_mac()
            try:
                set_interface_down(iface, SUDO_PASSWORD)
                set_interface_mac(iface, SUDO_PASSWORD, new_mac)
                set_interface_up(iface, SUDO_PASSWORD)
                msg = f"[ + ] {iface}: {new_mac}"
                self.append_notification(msg)
                logging.info(f"auto: MAC changed for {iface} to {new_mac}")
                append_change(AUTO_CHANGES_FILE,iface, old_mac, new_mac)
            except Exception as e:
                err = str(e)
                self.append_notification(f"[ - ] error: {err}")
        finally:
            set_tab_busy(self,False)
    def start_flooding_attack(self):
        iface = self.iface_combo.currentText()
        if not iface:
            self.append_notification("[ - ] error: No interface selected.")
            return
        try:
            total_changes = int(self.changes_edit.text().strip())
            total_duration = int(self.duration_edit.text().strip())
        except Exception:
            self.append_notification("[ - ] error: Please enter valid numbers for schedule.")
            return
        if not sudo_is_ready(self):
            return
        delay = total_duration / total_changes if total_changes else 0
        if delay < 0.05:
            self.append_notification("[ ! ] Warning: High frequency requested. Recommended delay is at least 0.05 sec per change.")
        set_tab_busy(self,True,"Running schedule",self.flood_attack_btn,"Running...")
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
        if not iface:
            self.append_notification("[ - ] error: No interface selected.")
            return
        if not sudo_is_ready(self):
            return
        default_mac = None
        if os.path.exists(DEFAULT_MAC_FILE):
            with open(DEFAULT_MAC_FILE, "r") as f:
                try:
                    data = json.load(f)
                    default_mac = data.get(iface)
                except Exception:
                    default_mac = None
        if not default_mac:
            self.append_notification(f"[ - ] error: Default MAC not found for {iface}")
            return
        set_tab_busy(self,True,"Restoring default",self.reset_default_btn,"Restoring...")
        try:
            try:
                set_interface_down(iface, SUDO_PASSWORD)
                self.append_notification(f"[ + ] Successfully brought down interface {iface}")
            except Exception as e:
                self.append_notification(f"[ - ] error while bringing down {iface} for reset: {str(e)}")
                return
            try:
                set_interface_mac(iface, SUDO_PASSWORD, default_mac)
                self.append_notification(f"[ + ] Successfully reset MAC for {iface}")
            except Exception as e:
                self.append_notification(f"[ - ] error resetting MAC: {str(e)}")
                return
            try:
                set_interface_up(iface, SUDO_PASSWORD)
                self.append_notification(f"[ + ] Interface {iface} is up")
            except Exception as e:
                self.append_notification(f"[ - ] error bringing up interface {iface} after reset: {str(e)}")
                return
        finally:
            set_tab_busy(self,False)
    def handle_worker_error(self, error_msg):
        self.append_notification(error_msg)
        if self.thread:
            self.thread.quit()
            self.thread.wait()
        set_tab_busy(self,False)
    def handle_worker_finished(self):
        self.append_notification("[ + ] MAC Flooding Attack Was Successfully Done!")
        if self.thread:
            self.thread.quit()
            self.thread.wait()
        set_tab_busy(self,False)
    def display_auto_log(self):
        dlg = LogDialog(LOG_FILE, filter_str="auto:", parent=self)
        dlg.exec()
    def display_auto_changes(self):
        dlg = ChangesDialog(AUTO_CHANGES_FILE, title="Auto MAC Changes", parent=self)
        dlg.exec()
    def export_auto_changes(self):
        export_changes_from_ui(self,AUTO_CHANGES_FILE,"Export Auto Changes","auto_changes.json")
class SmartMACTab(QWidget):
    def __init__(self):
        super().__init__()
        self.company_file = COMPANY_OUIS_FILE
        self.changes_file = SMART_CHANGES_FILE
        self.companies = {}
        self.initUI()
        self.loadCompanies()
    def initUI(self):
        left,right=make_two_column_page(self)
        panel,body=make_panel("Smart Vendor MAC")
        self.iface_combo = QComboBox()
        self.refresh_interfaces_btn = style_button(QPushButton("Refresh Interfaces"),"ghost")
        iface_holder=QWidget()
        iface_layout=QVBoxLayout(iface_holder)
        iface_layout.setContentsMargins(0,0,0,0)
        iface_layout.setSpacing(4)
        iface_label=QLabel("Network Interface")
        iface_label.setObjectName("FieldLabel")
        iface_row=QHBoxLayout()
        iface_row.setSpacing(8)
        self.iface_combo.setMinimumWidth(0)
        self.refresh_interfaces_btn.setMinimumWidth(0)
        self.refresh_interfaces_btn.setFixedHeight(46)
        self.iface_combo.setSizePolicy(QSizePolicy.Policy.Ignored,QSizePolicy.Policy.Fixed)
        self.refresh_interfaces_btn.setSizePolicy(QSizePolicy.Policy.Ignored,QSizePolicy.Policy.Fixed)
        iface_row.addWidget(self.iface_combo,1)
        iface_row.addWidget(self.refresh_interfaces_btn,1)
        iface_layout.addWidget(iface_label)
        iface_layout.addLayout(iface_row)
        body.addWidget(iface_holder)
        self.vendor_search_entry=QLineEdit()
        self.vendor_search_entry.setPlaceholderText("Search company or vendor")
        add_field(body,"Search Vendor",self.vendor_search_entry)
        self.company_combo = QComboBox()
        self.oui_combo = QComboBox()
        selector_layout=QHBoxLayout()
        selector_layout.setSpacing(10)
        selector_layout.addWidget(make_field_widget("Company",self.company_combo))
        selector_layout.addWidget(make_field_widget("OUI Prefix",self.oui_combo))
        body.addLayout(selector_layout)
        self.company_combo.currentIndexChanged.connect(self.updateOUICombo)
        self.vendor_search_entry.textChanged.connect(self.filterCompanies)
        self.add_company_btn = style_button(QPushButton("Add Company"),"ghost")
        self.edit_companies_btn = style_button(QPushButton("Edit Companies"),"ghost")
        body.addLayout(make_action_row(self.add_company_btn,self.edit_companies_btn))
        self.add_company_btn.clicked.connect(self.addCompany)
        self.edit_companies_btn.clicked.connect(self.editCompanies)
        self.generate_btn = style_button(QPushButton("Generate Vendor MAC"),"primary")
        self.generate_btn.clicked.connect(self.generateSmartMAC)
        self.random_vendor_btn = style_button(QPushButton("Random Vendor MAC"),"ghost")
        self.random_vendor_btn.clicked.connect(self.generateRandomVendorMAC)
        self.reset_btn = style_button(QPushButton("Reset Default"),"danger")
        self.reset_btn.clicked.connect(self.resetToDefault)
        body.addLayout(make_action_row(self.generate_btn,self.random_vendor_btn))
        body.addLayout(make_action_row(self.reset_btn))
        left.addWidget(panel)
        left.addStretch(1)
        status_panel,self.current_mac_label=make_metric_panel("Interface Status")
        right.addWidget(status_panel)
        console_panel,self.notification_area=make_console_panel("Smart Notifications",125,145)
        self.display_smart_log_btn = style_button(QPushButton("Display Smart Log"),"ghost")
        self.display_smart_changes_btn = style_button(QPushButton("Display Smart Changes"),"ghost")
        self.export_smart_changes_btn = style_button(QPushButton("Export Changes"),"ghost")
        self.restore_all_btn = style_button(QPushButton("Restore All Defaults"),"danger")
        console_panel.layout().addLayout(make_action_row(self.display_smart_log_btn,self.display_smart_changes_btn))
        console_panel.layout().addLayout(make_action_row(self.export_smart_changes_btn,self.restore_all_btn))
        right.addWidget(console_panel,1)
        self.action_state_label=add_action_state(status_panel)
        self.busy_buttons=[self.generate_btn,self.random_vendor_btn,self.reset_btn,self.refresh_interfaces_btn,self.restore_all_btn]
        self.display_smart_log_btn.clicked.connect(self.displaySmartLog)
        self.display_smart_changes_btn.clicked.connect(self.displaySmartChanges)
        self.export_smart_changes_btn.clicked.connect(self.exportSmartChanges)
        self.restore_all_btn.clicked.connect(self.restore_all_defaults)
        self.iface_combo.currentTextChanged.connect(self.refresh_current_mac)
        self.refresh_interfaces_btn.clicked.connect(self.reload_interfaces)
        self.reload_interfaces()
        attach_status_timer(self)
    def refresh_current_mac(self):
        update_live_interface_state(self,[self.reset_btn],"[ smar: - ]")
        self.updateSmartActionState()
    def reload_interfaces(self):
        interfaces=populate_interfaces(self.iface_combo,owner=self)
        save_default_for_interfaces(interfaces)
        has_interfaces=bool(interfaces)
        self.reset_btn.setEnabled(has_interfaces)
        self._suppress_live_notice=True
        self.refresh_current_mac()
        self._suppress_live_notice=False
        if has_interfaces:
            self.append_notification(f"[ smar: + ] Interfaces loaded: {', '.join(interfaces)}")
        elif getattr(self,"_interface_load_error",""):
            self.append_notification(f"[ smar: - ] {self._interface_load_error}")
        else:
            self.append_notification("[ smar: - ] No network interfaces found.")
        self.updateSmartActionState()
    def restore_all_defaults(self):
        restore_all_default_macs(self,"[ smar: - ]")
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
        self.filterCompanies(self.vendor_search_entry.text())
    def filterCompanies(self,text=""):
        current=self.company_combo.currentText()
        query=text.strip().lower()
        matches=[company for company in self.companies.keys() if query in company.lower()]
        self.company_combo.blockSignals(True)
        self.company_combo.clear()
        self.company_combo.addItems(matches)
        if current in matches:
            self.company_combo.setCurrentText(current)
        self.company_combo.blockSignals(False)
        self.company_combo.setEnabled(bool(matches))
        self.updateOUICombo()
    def updateOUICombo(self):
        company = self.company_combo.currentText()
        self.oui_combo.clear()
        if company in self.companies:
            for oui in self.companies[company]:
                self.oui_combo.addItem(oui)
        self.oui_combo.setEnabled(self.oui_combo.count()>0)
        self.updateSmartActionState()
    def updateSmartActionState(self):
        if getattr(self,"_busy",False):
            return
        has_interface=bool(self.iface_combo.currentText()) and getattr(self,"_interface_available",True) is not False
        has_vendor=bool(self.company_combo.currentText() and self.oui_combo.currentText())
        self.generate_btn.setEnabled(has_interface and has_vendor)
        self.random_vendor_btn.setEnabled(has_interface and any(self.companies.get(company) for company in self.companies))
    def addCompany(self):
        dialog = EditCompanyDialog("", [], self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_company_name, new_ouis = dialog.getData()
            if new_company_name:
                if new_company_name not in self.companies:
                    self.companies[new_company_name] = []
                self.companies[new_company_name].extend(new_ouis)
                self.companies[new_company_name] = list(set(self.companies[new_company_name]))
                with open(self.company_file, "w") as f:
                    json.dump(self.companies, f, indent=4)
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
        if not sudo_is_ready(self,"[ smar: - ]"):
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
        smart_mac = generate_vendor_mac(selected_oui)
        set_tab_busy(self,True,"Applying vendor MAC",self.generate_btn,"Applying...")
        try:
            self.applySmartMAC(iface,company,smart_mac)
        finally:
            set_tab_busy(self,False)
    def generateRandomVendorMAC(self):
        iface = self.iface_combo.currentText()
        if not iface:
            self.append_notification("[ smar: - ] error: No interface selected.")
            return
        if not sudo_is_ready(self,"[ smar: - ]"):
            return
        vendors=[company for company,ouis in self.companies.items() if ouis]
        if not vendors:
            self.append_notification("[ smar: - ] No vendor data available.")
            return
        company=random.choice(vendors)
        selected_oui=random.choice(self.companies[company])
        self.vendor_search_entry.blockSignals(True)
        self.vendor_search_entry.clear()
        self.vendor_search_entry.blockSignals(False)
        self.filterCompanies("")
        self.company_combo.setCurrentText(company)
        self.oui_combo.setCurrentText(selected_oui)
        set_tab_busy(self,True,"Applying random vendor MAC",self.random_vendor_btn,"Applying...")
        try:
            self.applySmartMAC(iface,company,generate_vendor_mac(selected_oui))
        finally:
            set_tab_busy(self,False)
    def applySmartMAC(self,iface,company,smart_mac):
        old_mac = get_current_mac_iface(iface)
        try:
            set_interface_down(iface, SUDO_PASSWORD)
            set_interface_mac(iface, SUDO_PASSWORD, smart_mac)
            set_interface_up(iface, SUDO_PASSWORD)
            self.append_notification(f"[ smar: + ] {company} on {iface}: {smart_mac}")
            logging.info(f"smar: MAC changed for {iface} to {smart_mac} using {company}")
            append_change(SMART_CHANGES_FILE,iface, old_mac, smart_mac)
        except Exception as e:
            self.append_notification(f"[ smar: - ] error: {str(e)}")
    def resetToDefault(self):
        iface = self.iface_combo.currentText()
        if not iface:
            self.append_notification("[ smar: - ] error: No interface selected.")
            return
        if not sudo_is_ready(self,"[ smar: - ]"):
            return
        default_mac = None
        if os.path.exists(DEFAULT_MAC_FILE):
            with open(DEFAULT_MAC_FILE, "r") as f:
                try:
                    data = json.load(f)
                    default_mac = data.get(iface)
                except:
                    default_mac = None
        if not default_mac:
            self.append_notification(f"[ smar: - ] error: Default MAC not found for {iface}")
            return
        set_tab_busy(self,True,"Restoring default",self.reset_btn,"Restoring...")
        try:
            try:
                set_interface_down(iface, SUDO_PASSWORD)
                self.append_notification(f"[ smar: + ] Successfully brought down interface {iface}")
            except Exception as e:
                self.append_notification(f"[ smar: - ] error bringing down {iface}: {str(e)}")
                return
            try:
                set_interface_mac(iface, SUDO_PASSWORD, default_mac)
                self.append_notification(f"[ smar: + ] Successfully reset MAC for {iface}")
            except Exception as e:
                self.append_notification(f"[ smar: - ] error resetting MAC: {str(e)}")
                return
            try:
                set_interface_up(iface, SUDO_PASSWORD)
                self.append_notification(f"[ smar: + ] Interface {iface} is up")
            except Exception as e:
                self.append_notification(f"[ smar: - ] error bringing up interface {iface}: {str(e)}")
                return
        finally:
            set_tab_busy(self,False)
    def displaySmartLog(self):
        dlg = LogDialog(LOG_FILE, filter_str="smar:", parent=self)
        dlg.exec()
    def displaySmartChanges(self):
        dlg = ChangesDialog(self.changes_file, title="Smart MAC Changes", parent=self)
        dlg.exec()
    def exportSmartChanges(self):
        export_changes_from_ui(self,self.changes_file,"Export Smart Changes","smart_changes.json","[ smar: + ]","[ smar: - ]")
    def append_notification(self, message):
        self.notification_area.append(message)
class SettingsTab(QWidget):
    def __init__(self,settings):
        super().__init__()
        self.settings=settings.copy()
        self.initUI()
    def initUI(self):
        left,right=make_two_column_page(self)
        panel,body=make_panel("Application Settings")
        self.theme_combo=QComboBox()
        self.theme_combo.addItems(THEME_LABELS.values())
        self.auto_restore_check=QCheckBox("Restore changed interfaces when closing")
        self.refresh_interval_entry=QLineEdit()
        self.refresh_interval_entry.setValidator(QIntValidator(2,60))
        self.refresh_interval_entry.setPlaceholderText("5")
        self.apply_ui_from_settings(self.settings)
        add_field(body,"Theme Mode",self.theme_combo)
        body.addWidget(self.auto_restore_check)
        add_field(body,"Refresh Interval Seconds",self.refresh_interval_entry)
        self.save_settings_btn=style_button(QPushButton("Save Settings"),"primary")
        self.reset_settings_btn=style_button(QPushButton("Reset Defaults"),"danger")
        body.addLayout(make_action_row(self.save_settings_btn,self.reset_settings_btn))
        left.addWidget(panel)
        left.addStretch(1)
        status_panel,self.settings_status_label=make_metric_panel("Settings Status")
        right.addWidget(status_panel)
        console_panel,self.notification_area=make_console_panel("Settings Notes",125,145)
        right.addWidget(console_panel,1)
        self.save_settings_btn.clicked.connect(self.save_current_settings)
        self.reset_settings_btn.clicked.connect(self.reset_settings)
        self.update_status()
    def apply_ui_from_settings(self,settings):
        self.theme_combo.setCurrentText(THEME_LABELS.get(settings.get("theme","dark_glass"),"Dark Glass"))
        self.auto_restore_check.setChecked(bool(settings.get("auto_restore_on_close",True)))
        self.refresh_interval_entry.setText(str(settings.get("refresh_interval_seconds",5)))
    def collect_settings(self):
        try:
            refresh=int(self.refresh_interval_entry.text().strip())
        except Exception:
            refresh=DEFAULT_SETTINGS["refresh_interval_seconds"]
        return {"theme":THEME_KEYS.get(self.theme_combo.currentText(),"dark_glass"),"auto_restore_on_close":self.auto_restore_check.isChecked(),"refresh_interval_seconds":max(2,min(60,refresh))}
    def save_current_settings(self):
        self.settings=save_settings(self.collect_settings())
        self.apply_ui_from_settings(self.settings)
        window=self.window()
        if hasattr(window,"apply_settings"):
            window.apply_settings(self.settings)
        else:
            apply_app_settings(self.settings)
        self.update_status()
        self.append_notification("[ + ] Settings saved and applied.")
    def reset_settings(self):
        self.settings=save_settings(DEFAULT_SETTINGS)
        self.apply_ui_from_settings(self.settings)
        window=self.window()
        if hasattr(window,"apply_settings"):
            window.apply_settings(self.settings)
        else:
            apply_app_settings(self.settings)
        self.update_status()
        self.append_notification("[ + ] Settings reset to defaults.")
    def update_status(self):
        theme=THEME_LABELS.get(self.settings.get("theme","dark_glass"),"Dark Glass")
        auto_restore="On" if self.settings.get("auto_restore_on_close",True) else "Off"
        refresh=self.settings.get("refresh_interval_seconds",5)
        self.settings_status_label.setText(f"Theme: {theme}\nAuto Restore: {auto_restore}\nRefresh: {refresh}s")
    def append_notification(self,message):
        self.notification_area.append(message)
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Kali Linux MAC Changer")
        self.resize(880, 540)
        self.setMinimumSize(820, 500)
        self.initUI()
        self.original_macs = {}
        for iface in get_interfaces():
            mac = get_current_mac_iface(iface)
            self.original_macs[iface] = mac
        with open(DEFAULT_MAC_FILE, "w") as f:
            json.dump(self.original_macs, f, indent=4)
    def initUI(self):
        central=QWidget()
        main_layout=QVBoxLayout(central)
        main_layout.setContentsMargins(16,16,16,16)
        main_layout.setSpacing(0)
        self.tabs = QTabWidget()
        self.tabs.setObjectName("MainTabs")
        self.tabs.tabBar().setExpanding(False)
        self.access_tab=SudoPasswordTab()
        self.manual_tab=ManualMACTab()
        self.auto_tab=AutoMACTab()
        self.smart_tab=SmartMACTab()
        self.settings_tab=SettingsTab(APP_SETTINGS)
        self.tabs.addTab(self.access_tab, "Access")
        self.tabs.addTab(self.manual_tab, "Manual")
        self.tabs.addTab(self.auto_tab, "Auto")
        self.tabs.addTab(self.smart_tab, "Smart")
        self.tabs.addTab(self.settings_tab, "Settings")
        main_layout.addWidget(self.tabs,1)
        self.setCentralWidget(central)
    def apply_settings(self,settings):
        apply_app_settings(settings)
        for tab in [self.manual_tab,self.auto_tab,self.smart_tab]:
            if hasattr(tab,"status_timer"):
                tab.status_timer.setInterval(INTERFACE_STATUS_REFRESH_MS)
        if hasattr(self,"settings_tab"):
            self.settings_tab.settings=APP_SETTINGS.copy()
            self.settings_tab.update_status()
    def closeEvent(self, event):
        if not APP_SETTINGS.get("auto_restore_on_close",True):
            event.accept()
            return
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
                if not SUDO_VALID or not SUDO_PASSWORD:
                    QMessageBox.warning(self,"Sudo Not Validated","Validate sudo password in the Access tab before restoring defaults.")
                    event.ignore()
                    return
                self.restore_default_macs()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()
    def restore_default_macs(self):
        if not SUDO_VALID or not SUDO_PASSWORD:
            QMessageBox.warning(self,"Sudo Not Validated","Validate sudo password in the Access tab before restoring defaults.")
            return
        for iface, orig_mac in self.original_macs.items():
            try:
                set_interface_down(iface, SUDO_PASSWORD)
                set_interface_mac(iface, SUDO_PASSWORD, orig_mac)
                set_interface_up(iface, SUDO_PASSWORD)
                logging.info(f"Restored default MAC for {iface} to {orig_mac}")
            except Exception as e:
                logging.error(f"Error restoring MAC for {iface}: {e}")
        QMessageBox.information(self, "MAC Restored", "Default MAC addresses have been restored.")
def main():
    ensure_runtime_files()
    setup_logging()
    apply_app_settings(load_settings())
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI",10))
    dark_palette = QPalette()
    dark_palette.setColor(QPalette.ColorRole.Window, QColor(7, 11, 18))
    dark_palette.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))
    dark_palette.setColor(QPalette.ColorRole.Base, QColor(8, 13, 23))
    dark_palette.setColor(QPalette.ColorRole.AlternateBase, QColor(18, 26, 40))
    dark_palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(255, 255, 255))
    dark_palette.setColor(QPalette.ColorRole.ToolTipText, QColor(255, 255, 255))
    dark_palette.setColor(QPalette.ColorRole.Text, QColor(255, 255, 255))
    dark_palette.setColor(QPalette.ColorRole.Button, QColor(31, 41, 55))
    dark_palette.setColor(QPalette.ColorRole.ButtonText, QColor(255, 255, 255))
    dark_palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
    dark_palette.setColor(QPalette.ColorRole.Link, QColor(96, 165, 250))
    dark_palette.setColor(QPalette.ColorRole.Highlight, QColor(37, 99, 235))
    dark_palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
    app.setPalette(dark_palette)
    app.setStyleSheet(get_app_style())
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
