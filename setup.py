from cx_Freeze import setup, Executable

# Define the executable
executables = [
    Executable(
        script="appqt_neo_ver3.py",
        target_name="FileTransferApp.exe",
        base="Win32GUI"  # Hides the console on Windows
    )
]

# Include PyQt5 dependencies and the platforms directory
build_exe_options = {
    "packages": [
        "PyQt5.QtCore",
        "PyQt5.QtWidgets",
        "PyQt5.QtGui",  # Added for completeness
        "socket",
        "threading",
        "os",
        "queue",
        "time",
        "logging",
        "struct"
    ],
    "include_files": [
        # Path to the PyQt5 platforms directory from your Python installation
        (r"C:\Users\Ankit Singh\AppData\Local\Programs\Python\Python310\Lib\site-packages\PyQt5\Qt5\plugins\platforms", "platforms")
    ],
    "excludes": [],  # No exclusions needed
    "include_msvcr": True  # Include Microsoft Visual C++ runtime, often needed for PyQt5
}

# Setup configuration
setup(
    name="FileTransferApp",
    version="1.0",
    description="File Transfer Application",
    options={"build_exe": build_exe_options},
    executables=executables
)