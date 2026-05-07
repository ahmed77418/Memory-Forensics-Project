import sys, os, subprocess, yara
from PyQt5.QtWidgets import *
from PyQt5.QtCore import QThread, pyqtSignal

class Worker(QThread):
    res = pyqtSignal(str)
    def __init__(self, cmd, is_yara, img, task_name):
        super().__init__()
        self.cmd = cmd
        self.is_yara = is_yara
        self.img = img
        self.task_name = task_name

    def run(self):
        try:
            if self.is_yara:
                rule_file = "rules.yar"
                if not os.path.exists(rule_file):
                    self.res.emit(f"[-] Error: '{rule_file}' not found!\n\nPlease place a YARA rules file named 'rules.yar' in the same folder.")
                    return
                
                rules = yara.compile(filepath=rule_file)
                matches = rules.match(self.img)
                
                if matches:
                    output = "[!] REAL MALWARE DETECTED IN MEMORY!\n--------------------------------------\n"
                    for m in matches:
                        output += f"Malware Name/Family: {m.rule}\n"
                    self.res.emit(output)
                else:
                    self.res.emit("[+] Clean: No Malware Found based on the provided rules.")
            else:
                p = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                out, err = p.communicate()
                if out:
                    filtered = self.filter_output(out, self.task_name)
                    self.res.emit(filtered)
                else:
                    self.res.emit(f"Error:\n{err}")
        except Exception as e:
            self.res.emit(f"Error: {str(e)}")

    def filter_output(self, text, task):
        lines = text.split('\n')
        
        if task == "info":
            os_ver = arch = time = "Unknown"
            for line in lines:
                if "NTBuildLab" in line: os_ver = line.split()[-1]
                if "Is64Bit" in line: arch = "64-bit" if "True" in line else "32-bit"
                if "SystemTime" in line: time = line.split('\t')[-1]
            return f"[+] Essential Image Info:\n-------------------------\nOS Version:   {os_ver}\nArchitecture: {arch}\nDump Time:    {time}"
            
        elif task == "credentials":
            res = "[+] Critical Registry Hives (For Passwords):\n--------------------------------------------\n"
            for line in lines:
                if "SAM" in line.upper() or "SYSTEM" in line.upper():
                    parts = line.split()
                    if len(parts) >= 2:
                        res += f"- Hive: {parts[1]}\n  Offset: {parts[0]}\n\n"
            return res if len(res.split('\n')) > 3 else "No SAM or SYSTEM hives found."

        elif task == "netscan_netstat":
            res = "[+] Active & Listening Connections:\n-----------------------------------\n"
            count = 0
            for line in lines:
                if "LISTENING" in line or "ESTABLISHED" in line:
                    parts = line.split()
                    if len(parts) >= 9:
                        proto = parts[1]
                        local = f"{parts[2]}:{parts[3]}"
                        foreign = f"{parts[4]}:{parts[5]}"
                        state = parts[6]
                        owner = parts[8]
                        res += f"[{state}] {proto} | {local} --> {foreign} | App: {owner}\n"
                        count += 1
            res += f"-----------------------------------\nTotal Active Connections: {count}"
            return res
            
        elif task == "pslist":
            res = "[+] Running Processes (Clean View):\n-----------------------------------\n"
            count = 0
            for line in lines:
                clean_line = line.replace('*', '').strip()
                parts = clean_line.split()
                if len(parts) > 5 and parts[0].isdigit():
                    pid = parts[0]
                    ppid = parts[1]
                    name = parts[2]
                    res += f"App: {name:<18} | PID: {pid:<5} | Parent: {ppid}\n"
                    count += 1
            res += f"-----------------------------------\nTotal Processes: {count}"
            return res
            
        return text 

class App(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Smart Memory Forensics")
        self.resize(800, 600)
        self.img = ""
        lay = QVBoxLayout(self)
        
        btn_load = QPushButton("Select Memory Dump")
        btn_load.clicked.connect(self.load)
        lay.addWidget(btn_load)

        os_lay = QHBoxLayout()
        os_lay.addWidget(QLabel("Target OS:"))
        self.os_cb = QComboBox()
        self.os_cb.addItems(["windows", "linux", "mac"])
        os_lay.addWidget(self.os_cb)
        lay.addLayout(os_lay)

        reqs = [
            ("info", "info"),
            ("pslist", "pslist"),
            ("netscan", "netscan_netstat"),
            ("hivelist", "credentials"),
            ("yara scan", "yara")
        ]
        
        for name, cmd in reqs:
            b = QPushButton(name)
            b.clicked.connect(lambda _, c=cmd: self.run_task(c))
            lay.addWidget(b)
            
        self.txt = QTextEdit()
        self.txt.setStyleSheet("background:black; color:lime; font-family: monospace; font-size: 14px;")
        lay.addWidget(self.txt)

    def load(self):
        self.img, _ = QFileDialog.getOpenFileName()
        if self.img: self.txt.setText(f"Loaded Dump: {self.img}")

    def run_task(self, task):
        if not self.img: return
        self.txt.setText("Processing... Please wait.")
        os_n = self.os_cb.currentText()
        is_yara = (task == "yara")
        
        cmd = []
        if not is_yara:
            t_cmd = "netscan" if task == "netscan_netstat" and os_n == "windows" else \
                    "netstat" if task == "netscan_netstat" else \
                    "registry.hivelist" if task == "credentials" and os_n == "windows" else \
                    "check_creds" if task == "credentials" else task
            
            if task == "pslist": t_cmd = "pstree" if os_n == "windows" else "pslist"

            cmd = ["vol", "-f", self.img, f"{os_n}.{t_cmd}"]

        self.w = Worker(cmd, is_yara, self.img, task)
        self.w.res.connect(self.txt.setText)
        self.w.start()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = App()
    w.show()
    app.exec_()
 
