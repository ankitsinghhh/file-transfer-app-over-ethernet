import sys
import os
import re
import wexpect
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFileDialog, QMessageBox, QPlainTextEdit
)
from PyQt5.QtCore import QThread, pyqtSignal

def find_remote_username(remote_ip, password, log_callback=None):
    """
    Attempt to discover the correct remote username by trying a list of candidates.
    It connects via SSH and runs 'whoami' on the remote machine.
    """
    # Expanded candidate list including testFileTransferUser which worked in your manual test.
    candidate_usernames = ["Administrator", "admin", "testFileTransferUser", "root", "user"]
    
    for username in candidate_usernames:
        if log_callback:
            log_callback(f"Trying username: {username}...")
        else:
            print(f"Trying username: {username}...")
        
        cmd = (
            f'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
            f'{username}@{remote_ip} "whoami"'
        )
        try:
            child = wexpect.spawn(cmd)
            # Expect either the confirmation prompt or the password prompt.
            index = child.expect([
                re.compile(r"(?i)are you sure you want to continue connecting"),
                re.compile(r"(?i)password:")
            ], timeout=20)
            if index == 0:
                if log_callback:
                    log_callback("Received SSH confirmation prompt. Sending 'yes'.")
                else:
                    print("Received SSH confirmation prompt. Sending 'yes'.")
                child.sendline("yes")
                child.expect(re.compile(r"(?i)password:"), timeout=20)
            
            # Send the provided password.
            child.sendline(password)
            child.expect(wexpect.EOF, timeout=20)
            output = child.before
            if isinstance(output, bytes):
                output = output.decode('utf-8', errors='ignore')
            
            # Log the output
            if log_callback:
                log_callback(f"Output for {username}: {output.strip()}")
            else:
                print(f"Output for {username}: {output.strip()}")
            
            # If we see a permission denied message, this candidate didn't work.
            if "permission denied" in output.lower():
                if log_callback:
                    log_callback(f"Username '{username}' failed authentication.")
                continue
            
            # If the output includes the username (case-insensitive), return it.
            if username.lower() in output.lower():
                if log_callback:
                    log_callback(f"Username '{username}' seems valid!")
                else:
                    print(f"Username '{username}' seems valid!")
                return username
        except Exception as e:
            if log_callback:
                log_callback(f"Error with username '{username}': {str(e)}")
            else:
                print(f"Error with username '{username}': {str(e)}")
            continue
    return None

class TransferWorker(QThread):
    result = pyqtSignal(bool, str)  # Emits (success, message)
    debug_signal = pyqtSignal(str)    # Emits debug messages as strings

    def __init__(self, file_path, remote_ip, password):
        super().__init__()
        self.file_path = file_path
        self.remote_ip = remote_ip
        self.password = password

    def run(self):
        try:
            def log(msg):
                self.debug_signal.emit(msg)
                print(msg)
            log("Starting to find remote username...")
            remote_username = find_remote_username(self.remote_ip, self.password, log_callback=log)
            if remote_username is None:
                log("Could not determine remote username.")
                self.result.emit(False, "Could not determine remote username.")
                return

            # Define the remote destination directory (adjust as needed)
            remote_path = "C:/Users/ankit/Desktop/receiver"

            # Build the SCP command using the discovered username.
            scp_command = (
                f'scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
                f'"{self.file_path}" "{remote_username}@{self.remote_ip}:{remote_path}"'
            )
            log(f"Executing SCP command: {scp_command}")

            child = wexpect.spawn(scp_command)
            index = child.expect([
                re.compile(r"(?i)are you sure you want to continue connecting"),
                re.compile(r"(?i)password:")
            ], timeout=20)
            if index == 0:
                log("Received SSH confirmation prompt for SCP. Sending 'yes'.")
                child.sendline("yes")
                child.expect(re.compile(r"(?i)password:"), timeout=20)
            log("Sending password for SCP...")
            child.sendline(self.password)
            child.expect(wexpect.EOF, timeout=60)
            log("SCP command completed successfully.")
            self.result.emit(True, f"File transferred successfully as '{remote_username}'!")
        except Exception as e:
            err_msg = f"File transfer failed: {str(e)}"
            self.result.emit(False, err_msg)
            print(err_msg)
            self.debug_signal.emit(err_msg)

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("File Transfer App")
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        # --- File selection ---
        file_layout = QHBoxLayout()
        self.file_line_edit = QLineEdit()
        self.file_line_edit.setPlaceholderText("Select file...")
        file_layout.addWidget(self.file_line_edit)
        self.browse_button = QPushButton("Browse")
        self.browse_button.clicked.connect(self.browse_file)
        file_layout.addWidget(self.browse_button)
        layout.addLayout(file_layout)

        # --- Remote IP input ---
        self.remote_ip_line_edit = QLineEdit()
        self.remote_ip_line_edit.setPlaceholderText("Enter remote IP (e.g., 192.168.1.101)")
        layout.addWidget(self.remote_ip_line_edit)

        # --- Password input ---
        self.password_line_edit = QLineEdit()
        self.password_line_edit.setPlaceholderText("Enter password")
        self.password_line_edit.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_line_edit)

        # --- Transfer button ---
        self.transfer_button = QPushButton("Transfer")
        self.transfer_button.clicked.connect(self.start_transfer)
        layout.addWidget(self.transfer_button)

        # --- Message label ---
        self.message_label = QLabel("")
        layout.addWidget(self.message_label)

        # --- Debug log area ---
        layout.addWidget(QLabel("Debug Log:"))
        self.debug_text = QPlainTextEdit()
        self.debug_text.setReadOnly(True)
        layout.addWidget(self.debug_text)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_line_edit.setText(file_path)

    def start_transfer(self):
        file_path = self.file_line_edit.text().strip()
        remote_ip = self.remote_ip_line_edit.text().strip()
        password = self.password_line_edit.text().strip()

        if not file_path:
            QMessageBox.warning(self, "Error", "Please select a file.")
            return
        if not remote_ip:
            QMessageBox.warning(self, "Error", "Please enter the remote IP.")
            return
        if not password:
            QMessageBox.warning(self, "Error", "Please enter a password.")
            return

        self.message_label.setText("Transferring file...")
        self.transfer_button.setEnabled(False)
        self.browse_button.setEnabled(False)

        # Start the background worker thread.
        self.worker = TransferWorker(file_path, remote_ip, password)
        self.worker.result.connect(self.on_transfer_finished)
        self.worker.debug_signal.connect(self.append_debug_message)
        self.worker.start()

    def append_debug_message(self, msg):
        """Append a debug message to the debug log area."""
        self.debug_text.appendPlainText(msg)

    def on_transfer_finished(self, success, message):
        self.transfer_button.setEnabled(True)
        self.browse_button.setEnabled(True)
        self.message_label.setText(message)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
