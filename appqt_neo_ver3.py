import sys
import socket
import threading
import os
import queue
import time
import logging
import struct
from PyQt5.QtWidgets import (
    QMainWindow, QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox,
    QStackedWidget, QListWidget, QPushButton, QTextEdit, QFileDialog, QMessageBox, QProgressBar
)
from PyQt5.QtCore import QTimer, pyqtSignal, QObject

# Set up logging to debug.log
logging.basicConfig(filename='debug.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Multicast settings
MULTICAST_GROUP = '224.0.0.1'
MULTICAST_PORT = 5007
TRANSFER_PORT = 8080
SAVE_DIR = "received_files"

if not os.path.exists(SAVE_DIR):
    os.makedirs(SAVE_DIR)

class TransferProgress(QObject):
    progress_updated = pyqtSignal(int)  # Percentage
    speed_updated = pyqtSignal(str)    # Real-time speed
    transfer_complete = pyqtSignal(str) # Average speed

    def __init__(self):
        super().__init__()
        self.start_time = None
        self.bytes_processed = 0
        self.total_size = 0
        self.last_update_time = 0
        self.last_bytes_processed = 0
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_metrics)

    def start(self, total_size):
        self.start_time = time.time()
        self.last_update_time = self.start_time
        self.bytes_processed = 0
        self.last_bytes_processed = 0
        self.total_size = total_size
        self.timer.start(100)  # Update every 100ms

    def stop(self):
        self.timer.stop()
        self.calculate_average_speed()

    def update_progress(self, bytes_processed):
        self.bytes_processed = bytes_processed
        if self.total_size > 0:
            percentage = int((self.bytes_processed / self.total_size) * 100)
            self.progress_updated.emit(percentage)
        self.update_metrics()

    def update_metrics(self):
        current_time = time.time()
        elapsed_time = current_time - self.last_update_time
        if elapsed_time >= 0.1:
            bytes_since_last = self.bytes_processed - self.last_bytes_processed
            if elapsed_time > 0:
                speed = bytes_since_last / elapsed_time / (1024 * 1024)  # MB/s
                self.speed_updated.emit(f"{speed:.2f} MB/s")
            self.last_update_time = current_time
            self.last_bytes_processed = self.bytes_processed

    def calculate_average_speed(self):
        total_time = time.time() - self.start_time
        if total_time > 0:
            avg_speed = self.bytes_processed / total_time / (1024 * 1024)  # MB/s
            self.transfer_complete.emit(f"Completed - Avg Speed: {avg_speed:.2f} MB/s")

class FileTransferWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("File Transfer App (Debug Version)")
        self.mode = "Receive"
        self.receivers = {}
        self.selected_receiver = None
        self.file_path = None
        self.active_threads = []
        self.stop_events = {}
        self.log_queue = queue.Queue()
        self.discovery_queue = queue.Queue()
        self.received_files_queue = queue.Queue()
        self.message_queue = queue.Queue()
        self.transfer_progress = TransferProgress()

        # Central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # IP selection
        ip_layout = QHBoxLayout()
        ip_label = QLabel("Select IP:")
        self.ip_combo = QComboBox()
        ips = self.get_local_ips()
        self.ip_combo.addItems(ips)
        if self.ip_combo.count() > 0:
            self.selected_ip = self.ip_combo.currentText()
        else:
            self.selected_ip = None
        self.ip_combo.currentTextChanged.connect(self.on_ip_change)
        ip_layout.addWidget(ip_label)
        ip_layout.addWidget(self.ip_combo)
        main_layout.addLayout(ip_layout)

        # Mode selection
        mode_layout = QHBoxLayout()
        mode_label = QLabel("Select Mode:")
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Send", "Receive"])
        self.mode_combo.setCurrentText("Receive")
        self.mode_combo.currentTextChanged.connect(self.on_mode_change)
        mode_layout.addWidget(mode_label)
        mode_layout.addWidget(self.mode_combo)
        main_layout.addLayout(mode_layout)

        # Stacked widget for modes
        self.stacked_widget = QStackedWidget()
        main_layout.addWidget(self.stacked_widget)

        # Receive Mode Page
        self.receive_page = QWidget()
        receive_layout = QVBoxLayout(self.receive_page)
        receive_label = QLabel("Receiver Mode: Listening for files...")
        self.received_files_list = QListWidget()
        self.receive_progress = QProgressBar()
        self.receive_speed_label = QLabel("Speed: 0.00 MB/s")
        self.receive_progress.setVisible(False)
        self.receive_speed_label.setVisible(False)
        receive_layout.addWidget(receive_label)
        receive_layout.addWidget(self.received_files_list)
        receive_layout.addWidget(self.receive_progress)
        receive_layout.addWidget(self.receive_speed_label)
        self.stacked_widget.addWidget(self.receive_page)

        # Send Mode Page
        self.send_page = QWidget()
        send_layout = QVBoxLayout(self.send_page)
        receivers_label = QLabel("Available Receivers:")
        self.receivers_list = QListWidget()
        self.receivers_list.itemSelectionChanged.connect(self.on_select_receiver)
        select_file_btn = QPushButton("Select File")
        select_file_btn.clicked.connect(self.select_file)
        self.file_label = QLabel("No file selected")
        transfer_btn = QPushButton("Transfer")
        transfer_btn.clicked.connect(self.transfer_file)
        self.speed_label = QLabel("Transfer Speed: 0.00 MB/s")
        self.send_progress = QProgressBar()
        send_layout.addWidget(receivers_label)
        send_layout.addWidget(self.receivers_list)
        send_layout.addWidget(select_file_btn)
        send_layout.addWidget(self.file_label)
        send_layout.addWidget(transfer_btn)
        send_layout.addWidget(self.speed_label)
        send_layout.addWidget(self.send_progress)
        self.stacked_widget.addWidget(self.send_page)

        # Set initial mode
        self.stacked_widget.setCurrentIndex(0)
        self.switch_mode("Receive")

        # Log window
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        main_layout.addWidget(self.log_text)

        # GUI update timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_gui)
        self.timer.start(100)

        # Connect signals
        self.transfer_progress.progress_updated.connect(self.update_progress)
        self.transfer_progress.speed_updated.connect(self.update_speed_label)
        self.transfer_progress.transfer_complete.connect(self.show_completion)

    def get_local_ips(self):
        """Fetch local IP addresses and log them."""
        ips = []
        try:
            for interface in socket.getaddrinfo(socket.gethostname(), None):
                if interface[0] == socket.AF_INET:
                    ip = interface[4][0]
                    if ip not in ips and ip != '127.0.0.1':
                        ips.append(ip)
            logging.info(f"Found IPs: {ips}")
        except Exception as e:
            logging.error(f"Error fetching IP addresses: {e}")
        return ips

    def on_ip_change(self, ip):
        """Handle IP selection change and log it."""
        self.selected_ip = ip
        logging.info(f"Selected IP: {ip}")
        if self.mode:
            self.switch_mode(self.mode)

    def on_mode_change(self, mode):
        self.mode = mode
        self.stacked_widget.setCurrentIndex(1 if mode == "Send" else 0)
        self.switch_mode(mode)

    def switch_mode(self, new_mode):
        for stop_event in self.stop_events.values():
            stop_event.set()
        for thread in self.active_threads:
            thread.join()
        self.active_threads.clear()
        self.stop_events.clear()
        self.receivers.clear()
        self.receivers_list.clear()
        self.selected_receiver = None

        if new_mode == "Send":
            self.start_sender_mode()
        else:
            self.start_receiver_mode()

    def start_receiver_mode(self):
        advertise_stop = threading.Event()
        receive_stop = threading.Event()
        self.stop_events['advertise'] = advertise_stop
        self.stop_events['receive'] = receive_stop
        advertise_thread = threading.Thread(target=self.advertise_presence, args=(advertise_stop,))
        receive_thread = threading.Thread(target=self.receive_file, args=(receive_stop,))
        advertise_thread.daemon = True
        receive_thread.daemon = True
        advertise_thread.start()
        receive_thread.start()
        self.active_threads.extend([advertise_thread, receive_thread])

    def start_sender_mode(self):
        discover_stop = threading.Event()
        self.stop_events['discover'] = discover_stop
        discover_thread = threading.Thread(target=self.discover_receivers, args=(discover_stop,))
        discover_thread.daemon = True
        discover_thread.start()
        self.active_threads.append(discover_thread)

    def advertise_presence(self, stop_event):
        """Advertise presence via multicast with logging."""
        if not self.selected_ip:
            logging.warning("No selected IP for advertising")
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self.selected_ip))
        message = f"{self.selected_ip}:{TRANSFER_PORT}".encode('utf-8')
        while not stop_event.is_set():
            try:
                logging.info(f"Sending advertisement from {self.selected_ip}")
                sock.sendto(message, (MULTICAST_GROUP, MULTICAST_PORT))
                time.sleep(5)
            except Exception as e:
                logging.error(f"Error in advertising: {e}")
        sock.close()

    def receive_file(self, stop_event):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.settimeout(1)
        try:
            server_sock.bind(('', TRANSFER_PORT))
            logging.info(f"Server socket bound to port {TRANSFER_PORT}")
        except Exception as e:
            logging.error(f"Error binding server socket: {e}")
            server_sock.close()
            return
        server_sock.listen(1)
        while not stop_event.is_set():
            try:
                client_sock, addr = server_sock.accept()
                with client_sock:
                    logging.info(f"Started receiving from {addr}")
                    self.receive_progress.setVisible(True)
                    self.receive_speed_label.setVisible(True)
                    header_length = struct.unpack('!I', client_sock.recv(4))[0]
                    header_data = client_sock.recv(header_length)
                    header = header_data.decode('utf-8').splitlines()
                    file_name = header[0]
                    file_size = int(header[1])
                    
                    self.transfer_progress.start(file_size)
                    file_path = os.path.join(SAVE_DIR, os.path.basename(file_name))
                    with open(file_path, 'wb') as f:
                        received = 0
                        while received < file_size:
                            chunk = client_sock.recv(min(1024, file_size - received))
                            if not chunk:
                                break
                            f.write(chunk)
                            received += len(chunk)
                            self.transfer_progress.update_progress(received)
                    
                    self.transfer_progress.stop()
                    self.receive_progress.setVisible(False)
                    self.receive_speed_label.setVisible(False)
                    if received == file_size:
                        self.received_files_queue.put(os.path.basename(file_name))
                    else:
                        logging.warning(f"Incomplete file received: {received}/{file_size} bytes")
            except socket.timeout:
                continue
            except Exception as e:
                logging.error(f"Error receiving file: {e}")
        server_sock.close()

    def discover_receivers(self, stop_event):
        """Discover receivers via multicast with logging."""
        if not self.selected_ip:
            logging.warning("No selected IP for discovery")
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Corrected option
        sock.settimeout(1)
        try:
            sock.bind(('', MULTICAST_PORT))
            logging.info(f"Bound to port {MULTICAST_PORT}")
        except Exception as e:
            logging.error(f"Error binding socket: {e}")
            sock.close()
            return
        mreq = socket.inet_aton(MULTICAST_GROUP) + socket.inet_aton(self.selected_ip)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            logging.info(f"Joined multicast group {MULTICAST_GROUP} on interface {self.selected_ip}")
        except Exception as e:
            logging.error(f"Error joining multicast group: {e}")
            sock.close()
            return
        while not stop_event.is_set():
            try:
                data, _ = sock.recvfrom(1024)
                receiver_info = data.decode('utf-8')
                logging.info(f"Received from multicast: {receiver_info}")
                if receiver_info not in self.receivers:
                    self.discovery_queue.put(receiver_info)
            except socket.timeout:
                continue
            except Exception as e:
                logging.error(f"Error receiving from multicast: {e}")
        sock.close()

    def on_select_receiver(self):
        selected_items = self.receivers_list.selectedItems()
        if selected_items:
            self.selected_receiver = selected_items[0].text()

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_path = file_path
            self.file_label.setText(f"Selected: {os.path.basename(file_path)}")

    def transfer_file(self):
        if not self.file_path or not self.selected_receiver:
            return
        ip, port = self.selected_receiver.split(':')
        transfer_thread = threading.Thread(target=self.perform_transfer, args=(ip, int(port)))
        transfer_thread.daemon = True
        transfer_thread.start()
        self.active_threads.append(transfer_thread)

    def perform_transfer(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            with open(self.file_path, 'rb') as f:
                file_name = os.path.basename(self.file_path)
                file_size = os.path.getsize(self.file_path)
                header = f"{file_name}\n{file_size}\n".encode('utf-8')
                sock.send(struct.pack('!I', len(header)))
                sock.send(header)
                
                self.transfer_progress.start(file_size)
                bytes_sent = 0
                while True:
                    chunk = f.read(1024)
                    if not chunk:
                        break
                    sock.send(chunk)
                    bytes_sent += len(chunk)
                    self.transfer_progress.update_progress(bytes_sent)
            
            self.transfer_progress.stop()
            sock.close()
            self.message_queue.put(("info", "File transferred successfully!"))
        except Exception as e:
            self.message_queue.put(("error", f"Failed to transfer file: {e}"))

    def update_progress(self, percentage):
        if self.mode == "Send":
            self.send_progress.setValue(percentage)
        else:
            self.receive_progress.setValue(percentage)

    def update_speed_label(self, speed):
        if self.mode == "Send":
            self.speed_label.setText(f"Transfer Speed: {speed}")
        else:
            self.receive_speed_label.setText(f"Speed: {speed}")

    def show_completion(self, message):
        if self.mode == "Send":
            self.speed_label.setText(message)
        else:
            self.receive_speed_label.setText(message)
        self.log_queue.put(message)

    def update_gui(self):
        while not self.log_queue.empty():
            self.log_text.append(self.log_queue.get())
        while not self.received_files_queue.empty():
            self.received_files_list.addItem(self.received_files_queue.get())
        while not self.discovery_queue.empty():
            receiver_key = self.discovery_queue.get()
            if receiver_key not in self.receivers:
                self.receivers[receiver_key] = True
                self.receivers_list.addItem(receiver_key)
        while not self.message_queue.empty():
            msg_type, msg = self.message_queue.get()
            if msg_type == "info":
                QMessageBox.information(self, "Info", msg)
            else:
                QMessageBox.critical(self, "Error", msg)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FileTransferWindow()
    window.show()
    sys.exit(app.exec_())