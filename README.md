# File Transfer App Over Ethernet

This project is a personal endeavor to create a file transfer application over Ethernet. It was developed to address the issue of frequent ping failures between laptops connected via Ethernet cables. The application not only solves this problem but also facilitates file transfers over Ethernet.

## Features

- **File Transfer**: Transfer files between devices connected via Ethernet.
- **Multicast Communication**: Uses multicast to discover devices on the network.
- **Progress Tracking**: Real-time progress and speed tracking of file transfers.
- **Graphical User Interface**: Built using PyQt5 for a user-friendly experience.

## Getting Started

### Prerequisites

- **Python**: Ensure you have Python installed on your system.
- **PyQt5**: The application uses PyQt5 for the GUI. You can install it using pip:
  ```bash
  pip install PyQt5
  ```
- **cx_Freeze**: Used to create an executable of the application. Install it via pip:
  ```bash
  pip install cx_Freeze
  ```

### Running the Application

1. **Clone the Repository**: Clone this repository to your local machine.
2. **Navigate to the Directory**: Open a terminal and navigate to the project directory.
3. **Run the Application**: Execute the main file using Python:
   ```bash
   python appqt_neo_ver3.py
   ```

### Building the Executable

To create an executable using `cx_Freeze`, ensure you have a `setup.py` file configured. Run the following command in the terminal:
```bash
python setup.py build
```
This will generate an executable in the `build` folder.

## How It Works

The application uses several key libraries and techniques:

- **PyQt5**: Provides the graphical user interface components.
- **Socket Programming**: Utilizes Python's `socket` library for network communication.
- **Multithreading**: Uses `threading` to handle multiple tasks simultaneously, such as sending and receiving files.
- **Logging**: Logs important events and errors to `debug.log` for debugging purposes.

### Key Components

- **TransferProgress**: Manages the progress and speed of file transfers.
- **FileTransferWindow**: The main window of the application, handling user interactions and file transfer logic.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request for any improvements or bug fixes.

