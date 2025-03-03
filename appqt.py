import sys
import os
import re
import wexpect
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFileDialog, QMessageBox
)
from PyQt5.QtCore import QThread, pyqtSignal

# Worker thread for running the SCP command in the background
class TransferWorker(QThread):
    result = pyqtSignal(bool, str)  # Signal to send (success, message)

    def __init__(self, file_path, password):
        super().__init__()
        self.file_path = file_path
        self.password = password

    def run(self):
        try:
            # Define remote destination directory on the target host
            remote_path = "C:/Users/ankit/Desktop/receiver"
            # Build the SCP command using the provided file path
            scp_command = (
                f'scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
                f'"{self.file_path}" "testFileTransferUser@192.168.1.101:{remote_path}"'
            )
            print("Executing:", scp_command)
            
            # Spawn the SCP process using wexpect
            child = wexpect.spawn(scp_command)
            
            # Wait for either a prompt to confirm the host or a password prompt
            index = child.expect([
                re.compile(r"(?i)are you sure you want to continue connecting"),
                re.compile(r"(?i)password:")
            ], timeout=20)
            
            # If prompted, send "yes" and then wait for the password prompt
            if index == 0:
                child.sendline("yes")
                child.expect(re.compile(r"(?i)password:"), timeout=20)
            
            # Send the password and wait for process completion
            child.sendline(self.password)
            child.expect(wexpect.EOF, timeout=60)
            
            self.result.emit(True, "File transferred successfully!")
        except Exception as e:
            self.result.emit(False, f"File transfer failed: {str(e)}")

# Main application window
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("File Transfer App")
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        # File selection row
        file_layout = QHBoxLayout()
        self.file_line_edit = QLineEdit()
        self.file_line_edit.setPlaceholderText("Select file...")
        file_layout.addWidget(self.file_line_edit)

        self.browse_button = QPushButton("Browse")
        self.browse_button.clicked.connect(self.browse_file)
        file_layout.addWidget(self.browse_button)
        layout.addLayout(file_layout)

        # Password input
        self.password_line_edit = QLineEdit()
        self.password_line_edit.setPlaceholderText("Enter password")
        self.password_line_edit.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_line_edit)

        # Transfer button
        self.transfer_button = QPushButton("Transfer")
        self.transfer_button.clicked.connect(self.start_transfer)
        layout.addWidget(self.transfer_button)

        # Message label for success/failure notifications
        self.message_label = QLabel("")
        layout.addWidget(self.message_label)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_line_edit.setText(file_path)

    def start_transfer(self):
        file_path = self.file_line_edit.text().strip()
        password = self.password_line_edit.text().strip()

        if not file_path:
            QMessageBox.warning(self, "Error", "Please select a file.")
            return
        if not password:
            QMessageBox.warning(self, "Error", "Please enter a password.")
            return

        self.message_label.setText("Transferring file...")
        self.transfer_button.setEnabled(False)
        self.browse_button.setEnabled(False)

        # Start the background transfer worker thread
        self.worker = TransferWorker(file_path, password)
        self.worker.result.connect(self.on_transfer_finished)
        self.worker.start()

    def on_transfer_finished(self, success, message):
        # Re-enable controls
        self.transfer_button.setEnabled(True)
        self.browse_button.setEnabled(True)
        self.message_label.setText(message)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
