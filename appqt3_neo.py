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
    QStackedWidget, QListWidget, QPushButton, QTextEdit, QFileDialog, QMessageBox
)
from PyQt5.QtCore import QTimer

# Set up logging
logging.basicConfig(filename='debug.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Multicast settings
MULTICAST_GROUP = '224.0.0.1'
MULTICAST_PORT = 5007
TRANSFER_PORT = 8080
SAVE_DIR = "received_files"

if not os.path.exists(SAVE_DIR):
    os.makedirs(SAVE_DIR)

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

        # Central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # IP selection
        ip_layout = QHBoxLayout()
        ip_label = QLabel("Select IP:")
        self.ip_combo = QComboBox()
        self.ip_combo.addItems(self.get_local_ips())
        if self.ip_combo.count() > 0:
            self.selected_ip = self.ip_combo.currentText()
        else:
            self.selected_ip = None
            self.log_queue.put("No IP addresses found. Please check your network.")
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

        # Receive Mode Page (index 0)
        self.receive_page = QWidget()
        receive_layout = QVBoxLayout(self.receive_page)
        receive_label = QLabel("Receiver Mode: Listening for files...")
        self.received_files_list = QListWidget()
        receive_layout.addWidget(receive_label)
        receive_layout.addWidget(self.received_files_list)
        self.stacked_widget.addWidget(self.receive_page)

        # Send Mode Page (index 1)
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
        send_layout.addWidget(receivers_label)
        send_layout.addWidget(self.receivers_list)
        send_layout.addWidget(select_file_btn)
        send_layout.addWidget(self.file_label)
        send_layout.addWidget(transfer_btn)
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

        logging.debug("FileTransferWindow initialized.")
        self.log_queue.put("Debug version initialized. Default mode: Receive.")

    def get_local_ips(self):
        ips = []
        try:
            for interface in socket.getaddrinfo(socket.gethostname(), None):
                if interface[0] == socket.AF_INET:
                    ip = interface[4][0]
                    if ip not in ips and ip != '127.0.0.1':
                        ips.append(ip)
        except Exception as e:
            logging.error(f"Error fetching IP addresses: {e}")
            self.log_queue.put(f"Error fetching IP addresses: {e}")
        return ips

    def on_ip_change(self, ip):
        self.selected_ip = ip
        msg = f"Selected IP: {ip}"
        logging.debug(msg)
        self.log_queue.put(msg)
        if self.mode:
            self.switch_mode(self.mode)

    def on_mode_change(self, mode):
        logging.debug(f"on_mode_change called. New mode: {mode}")
        self.mode = mode
        if mode == "Send":
            self.stacked_widget.setCurrentIndex(1)
        else:
            self.stacked_widget.setCurrentIndex(0)
        self.switch_mode(mode)

    def switch_mode(self, new_mode):
        logging.debug(f"switch_mode called. New mode: {new_mode}")
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
        msg = f"Switched to {new_mode} mode"
        logging.debug(msg)
        self.log_queue.put(msg)

    def start_receiver_mode(self):
        logging.debug("start_receiver_mode called.")
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
        logging.debug("start_sender_mode called.")
        discover_stop = threading.Event()
        self.stop_events['discover'] = discover_stop
        discover_thread = threading.Thread(target=self.discover_receivers, args=(discover_stop,))
        discover_thread.daemon = True
        discover_thread.start()
        self.active_threads.append(discover_thread)

    def advertise_presence(self, stop_event):
        if not self.selected_ip:
            self.log_queue.put("No IP selected for advertising.")
            return
        self.log_queue.put(f"Advertising presence with IP: {self.selected_ip}")
        logging.debug(f"advertise_presence thread started with IP: {self.selected_ip}")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self.selected_ip))
                logging.debug(f"Set multicast interface to {self.selected_ip}")
            except Exception as e:
                logging.error(f"Failed to set multicast interface: {e}")
                self.log_queue.put(f"Failed to set multicast interface: {e}")
                return
            message = f"{self.selected_ip}:{TRANSFER_PORT}".encode('utf-8')
            while not stop_event.is_set():
                try:
                    sock.sendto(message, (MULTICAST_GROUP, MULTICAST_PORT))
                    logging.debug(f"Advertised {message.decode()} to {MULTICAST_GROUP}:{MULTICAST_PORT}")
                    time.sleep(5)
                except Exception as e:
                    logging.error(f"Error in advertising: {e}")
                    self.log_queue.put(f"Error in advertising: {e}")
            sock.close()
            logging.debug("advertise_presence thread stopped.")
        except Exception as e:
            logging.error(f"Socket error in advertise_presence: {e}")
            self.log_queue.put(f"Socket error in advertise_presence: {e}")

    def receive_file(self, stop_event):
        self.log_queue.put("receive_file thread started")
        logging.debug("receive_file thread started.")
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.settimeout(1)
        try:
            server_sock.bind(('', TRANSFER_PORT))
            server_sock.listen(1)
            logging.debug(f"Bound to TCP port {TRANSFER_PORT} for receiving.")
        except Exception as e:
            logging.error(f"Receiver bind error: {e}")
            self.log_queue.put(f"Receiver bind error: {e}")
            return
        while not stop_event.is_set():
            try:
                client_sock, addr = server_sock.accept()
                logging.debug(f"Connection accepted from {addr}")
                with client_sock:
                    # Read header length (4 bytes)
                    header_length_data = client_sock.recv(4)
                    if len(header_length_data) < 4:
                        logging.error("Failed to read header length")
                        continue
                    header_length = struct.unpack('!I', header_length_data)[0]
                    
                    # Read the header
                    header_data = b''
                    while len(header_data) < header_length:
                        chunk = client_sock.recv(header_length - len(header_data))
                        if not chunk:
                            break
                        header_data += chunk
                    if len(header_data) < header_length:
                        logging.error("Failed to read complete header")
                        continue
                    
                    # Decode and parse the header
                    header = header_data.decode('utf-8').splitlines()
                    if len(header) < 2:
                        logging.error("Invalid header received")
                        continue
                    file_name = header[0]
                    file_size = int(header[1])
                    
                    # Receive the file content
                    file_path = os.path.join(SAVE_DIR, os.path.basename(file_name))
                    with open(file_path, 'wb') as f:
                        received = 0
                        while received < file_size:
                            chunk = client_sock.recv(min(1024, file_size - received))
                            if not chunk:
                                break
                            f.write(chunk)
                            received += len(chunk)
                    if received == file_size:
                        msg = f"Received: {file_name} from {addr}"
                        logging.debug(msg)
                        self.log_queue.put(msg)
                        self.received_files_queue.put(os.path.basename(file_name))
                    else:
                        logging.error(f"Incomplete file received: {received}/{file_size} bytes")
            except socket.timeout:
                continue
            except Exception as e:
                logging.error(f"Error receiving file: {e}")
                self.log_queue.put(f"Error receiving file: {e}")
        server_sock.close()
        logging.debug("receive_file thread stopped.")

    def discover_receivers(self, stop_event):
        if not self.selected_ip:
            self.log_queue.put("No IP selected for discovery.")
            return
        self.log_queue.put(f"Discovering receivers with IP: {self.selected_ip}")
        logging.debug(f"discover_receivers thread started with IP: {self.selected_ip}")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1)
            sock.bind(('', MULTICAST_PORT))
            logging.debug(f"Bound UDP socket for discovery on port {MULTICAST_PORT}")
            mreq = socket.inet_aton(MULTICAST_GROUP) + socket.inet_aton(self.selected_ip)
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                logging.debug(f"Joined multicast group {MULTICAST_GROUP} on {self.selected_ip}")
            except Exception as e:
                logging.error(f"Failed to join multicast group: {e}")
                self.log_queue.put(f"Failed to join multicast group: {e}")
                return
            while not stop_event.is_set():
                try:
                    data, _ = sock.recvfrom(1024)
                    receiver_info = data.decode('utf-8')
                    logging.debug(f"Discovered receiver info: {receiver_info}")
                    if receiver_info not in self.receivers:
                        self.discovery_queue.put(receiver_info)
                except socket.timeout:
                    continue
                except Exception as e:
                    logging.error(f"Error in discovery: {e}")
                    self.log_queue.put(f"Error in discovery: {e}")
            sock.close()
            logging.debug("discover_receivers thread stopped.")
        except Exception as e:
            logging.error(f"Discovery setup error: {e}")
            self.log_queue.put(f"Discovery setup error: {e}")

    def on_select_receiver(self):
        selected_items = self.receivers_list.selectedItems()
        if selected_items:
            self.selected_receiver = selected_items[0].text()
            msg = f"Selected receiver: {self.selected_receiver}"
            logging.debug(msg)
            self.log_queue.put(msg)

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_path = file_path
            file_basename = os.path.basename(file_path)
            self.file_label.setText(f"Selected: {file_basename}")
            msg = f"File selected: {file_path}"
            logging.debug(msg)
            self.log_queue.put(msg)

    def transfer_file(self):
        logging.debug("transfer_file called.")
        if not self.file_path:
            self.message_queue.put(("error", "Please select a file first!"))
            return
        if not self.selected_receiver:
            self.message_queue.put(("error", "Please select a receiver first!"))
            return
        ip, port = self.selected_receiver.split(':')
        logging.debug(f"Starting file transfer thread to {ip}:{port}")
        transfer_thread = threading.Thread(target=self.perform_transfer, args=(ip, int(port)))
        transfer_thread.daemon = True
        transfer_thread.start()
        self.active_threads.append(transfer_thread)

    def perform_transfer(self, ip, port):
        logging.debug(f"perform_transfer started. IP={ip}, Port={port}, File={self.file_path}")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            logging.debug("Socket connected.")
            with open(self.file_path, 'rb') as f:
                file_name = os.path.basename(self.file_path)
                file_size = os.path.getsize(self.file_path)
                # Create and encode the header
                header = f"{file_name}\n{file_size}\n".encode('utf-8')
                header_length = len(header)
                # Send header length as a 4-byte integer
                sock.send(struct.pack('!I', header_length))
                # Send the header
                sock.send(header)
                # Send file content
                bytes_sent = 0
                while True:
                    chunk = f.read(1024)
                    if not chunk:
                        break
                    sock.send(chunk)
                    bytes_sent += len(chunk)
                logging.debug(f"File transfer completed. Total bytes sent: {bytes_sent}")
            sock.close()
            msg = f"File transferred to {self.selected_receiver}"
            logging.debug(msg)
            self.log_queue.put(msg)
            self.message_queue.put(("info", "File transferred successfully!"))
        except Exception as e:
            err_msg = f"Transfer error: {e}"
            logging.error(err_msg)
            self.log_queue.put(err_msg)
            self.message_queue.put(("error", f"Failed to transfer file: {e}"))

    def update_gui(self):
        while not self.log_queue.empty():
            message = self.log_queue.get()
            self.log_text.append(message)
        while not self.received_files_queue.empty():
            file_name = self.received_files_queue.get()
            self.received_files_list.addItem(file_name)
        while not self.discovery_queue.empty():
            receiver_key = self.discovery_queue.get()
            if receiver_key not in self.receivers:
                self.receivers[receiver_key] = True
                self.receivers_list.addItem(receiver_key)
                disc_msg = f"Discovered: {receiver_key}"
                logging.debug(disc_msg)
                self.log_text.append(disc_msg)
        while not self.message_queue.empty():
            msg_type, msg = self.message_queue.get()
            if msg_type == "info":
                QMessageBox.information(self, "Info", msg)
            elif msg_type == "error":
                QMessageBox.critical(self, "Error", msg)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FileTransferWindow()
    window.show()
    sys.exit(app.exec_())