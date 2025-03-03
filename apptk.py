import socket
import threading
import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import logging
import sys
import time

# Set up logging
logging.basicConfig(filename='debug.log', level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Multicast settings for receiver discovery
MULTICAST_GROUP = '224.0.0.1'
MULTICAST_PORT = 5000
TRANSFER_PORT = 8080
SAVE_DIR = "received_files"

# Ensure save directory exists
if not os.path.exists(SAVE_DIR):
    os.makedirs(SAVE_DIR)

# Receiver Mode: Advertise presence and listen for file transfers
def receiver_mode():
    def advertise_presence():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        my_ip = socket.gethostbyname(socket.gethostname())
        message = f"{my_ip}:{TRANSFER_PORT}".encode('utf-8')
        while True:
            try:
                sock.sendto(message, (MULTICAST_GROUP, MULTICAST_PORT))
                time.sleep(5)  # Advertise every 5 seconds
            except Exception as e:
                logging.error(f"Error in advertising: {e}")

    def receive_file():
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(('', TRANSFER_PORT))
        server_sock.listen(1)
        receiver_window.insert(tk.END, "Listening for incoming files...\n")
        
        while True:
            try:
                client_sock, addr = server_sock.accept()
                receiver_window.insert(tk.END, f"Connection from {addr}\n")
                with client_sock:
                    data = client_sock.recv(1024).decode('utf-8').splitlines()
                    if len(data) < 2:
                        logging.error("Invalid transfer header received")
                        continue
                    file_name = data[0]
                    file_size = int(data[1])
                    
                    file_path = os.path.join(SAVE_DIR, os.path.basename(file_name))
                    with open(file_path, 'wb') as f:
                        received = 0
                        while received < file_size:
                            chunk = client_sock.recv(1024)
                            if not chunk:
                                break
                            f.write(chunk)
                            received += len(chunk)
                    receiver_window.insert(tk.END, f"Received: {file_name}\n")
            except Exception as e:
                logging.error(f"Error receiving file: {e}")
                receiver_window.insert(tk.END, f"Error: {e}\n")

    # Receiver GUI
    root = tk.Tk()
    root.title("File Transfer - Receiver Mode")
    global receiver_window
    receiver_window = scrolledtext.ScrolledText(root, width=50, height=20)
    receiver_window.pack(padx=10, pady=10)
    
    # Start advertising and listening in separate threads
    threading.Thread(target=advertise_presence, daemon=True).start()
    threading.Thread(target=receive_file, daemon=True).start()
    
    root.mainloop()

# Sender Mode: Discover receivers and send files
class SenderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Transfer - Sender Mode")
        self.receivers = {}
        self.selected_receiver = None
        self.file_path = None
        
        # GUI Components
        tk.Label(root, text="Available Receivers:").pack(pady=5)
        self.receiver_listbox = tk.Listbox(root, height=10, width=50)
        self.receiver_listbox.pack(pady=5)
        self.receiver_listbox.bind('<<ListboxSelect>>', self.on_select_receiver)
        
        tk.Button(root, text="Select File", command=self.select_file).pack(pady=5)
        self.file_label = tk.Label(root, text="No file selected")
        self.file_label.pack(pady=5)
        
        tk.Button(root, text="Transfer", command=self.transfer_file).pack(pady=5)
        
        self.log_window = scrolledtext.ScrolledText(root, width=50, height=10)
        self.log_window.pack(padx=10, pady=10)
        
        # Start receiver discovery
        self.discover_receivers()

    def discover_receivers(self):
        def listen_multicast():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('', MULTICAST_PORT))
            mreq = socket.inet_aton(MULTICAST_GROUP) + socket.inet_aton('0.0.0.0')
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            
            while True:
                try:
                    data, addr = sock.recvfrom(1024)
                    receiver_info = data.decode('utf-8')
                    ip, port = receiver_info.split(':')
                    receiver_key = f"{ip}:{port}"
                    if receiver_key not in self.receivers:
                        self.receivers[receiver_key] = {'ip': ip, 'port': int(port)}
                        self.receiver_listbox.insert(tk.END, receiver_key)
                        self.log_window.insert(tk.END, f"Discovered: {receiver_key}\n")
                except Exception as e:
                    logging.error(f"Error in discovery: {e}")
                    self.log_window.insert(tk.END, f"Error: {e}\n")
        
        threading.Thread(target=listen_multicast, daemon=True).start()

    def on_select_receiver(self, event):
        selection = self.receiver_listbox.curselection()
        if selection:
            self.selected_receiver = self.receiver_listbox.get(selection[0])
            self.log_window.insert(tk.END, f"Selected receiver: {self.selected_receiver}\n")

    def select_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            self.file_label.config(text=f"Selected: {os.path.basename(self.file_path)}")
            self.log_window.insert(tk.END, f"File selected: {self.file_path}\n")

    def transfer_file(self):
        if not self.file_path:
            messagebox.showerror("Error", "Please select a file first!")
            return
        if not self.selected_receiver:
            messagebox.showerror("Error", "Please select a receiver first!")
            return
        
        receiver_info = self.receivers[self.selected_receiver]
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((receiver_info['ip'], receiver_info['port']))
            
            with open(self.file_path, 'rb') as f:
                file_name = os.path.basename(self.file_path)
                file_size = os.path.getsize(self.file_path)
                
                # Send file name and size
                sock.send(f"{file_name}\n{file_size}\n".encode('utf-8'))
                
                # Send file content
                while True:
                    chunk = f.read(1024)
                    if not chunk:
                        break
                    sock.send(chunk)
            
            sock.close()
            self.log_window.insert(tk.END, f"File transferred to {self.selected_receiver}\n")
            messagebox.showinfo("Success", "File transferred successfully!")
        except Exception as e:
            logging.error(f"Transfer error: {e}")
            self.log_window.insert(tk.END, f"Transfer error: {e}\n")
            messagebox.showerror("Error", f"Failed to transfer file: {e}")

def sender_mode():
    root = tk.Tk()
    app = SenderApp(root)
    root.mainloop()

# Main entry point to select mode
if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ['send', 'receive']:
        print("Usage: python file_transfer_app.py [send|receive]")
        sys.exit(1)
    
    mode = sys.argv[1]
    if mode == 'send':
        sender_mode()
    elif mode == 'receive':
        receiver_mode()