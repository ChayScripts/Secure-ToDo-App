# Secure-ToDo-App

**Simple and secure desktop To-Do app to organize and protect all your tasks easily.**

***

## 🚀 Overview

Secure ToDo App is a modern, privacy-focused desktop to-do list application built with PyQt5.  
All your tasks are encrypted with your password and stored only on your computer (never in the cloud).  
Fast, beautiful, and designed for busy professionals who care about security and usability.

***

## 🔥 Features

- **🔐 End-to-End Encryption:** All your data is password-protected and strongly encrypted.
- **🖥️ Beautiful Desktop UI:** Modern, responsive PyQt5 interface—easy on the eyes, fast on the desktop.
- **📝 Comprehensive Task Management:** Add priorities, notes, status, dates, durations, completion percentage, overdue tracking, and more.
- **📋 Task Tabs:** Instantly switch between Active and Completed tasks.
- **🎨 Color-Coded Priorities & Status:** Easily spot urgent, normal, and completed tasks at a glance.
- **✏️ Edit Fast:** Select any task and edit all details in a single click.
- **🗑️ Multi-Select Delete:** Bulk-delete tasks with confirmation.
- **💾 Local Encrypted Storage:** No internet connection, no cloud storage, and no risk.
- **🔑 Change Password:** Update your password and re-encrypt your data at any time.
- **📦 Single-file EXE:** Packaged for easy portable use on any Windows machine.
- **🛡️ No Data Sync or Cloud:** Your tasks and details never leave your device.

***

## 🖼️ Screenshots

<p align = "center"><img src = "https://raw.githubusercontent.com/ChayScripts/Secure-ToDo-App/refs/heads/main/App%20Password%20Setup.png"></p><p align = "center">  
<b> First Time Setup </b>
</p>

<p align = "center"><img src = "https://raw.githubusercontent.com/ChayScripts/Secure-ToDo-App/refs/heads/main/Secure%20ToDo%20App.png"></p><p align = "center">  
<b> Secure ToDo App </b>
</p>

***

## 🛠️ How to Run

### **Prerequisites**
- Windows 10/11
- [Python 3.8+](https://www.python.org/downloads/) (if running from source)
- [PyQt5](https://pypi.org/project/PyQt5/) installed: `pip install pyqt5`
- [PyInstaller](https://pypi.org/project/pyinstaller/) (for .exe generation): `pip install pyinstaller`

### **Run from Source**

```bash
python app.py
```

### **Build a Standalone EXE**
1. Install PyInstaller:  
   `pip install pyinstaller`
2. Build the executable:
   ```bash
   # Todo_app.ico file is available in this repository.
   pyinstaller --onefile --windowed --icon=Todo_app.ico --name "Secure ToDo App" app.py --add-data "Todo_app.ico;."
   ```
   If you get an error that "pyinstaller is not recognized as an internal or external command", run `python -m pip show pyinstaller` command to find the location. Navigate to that location and run above command. 
3. Find your `.exe` in the `dist/` folder!

***

## 💡 Usage

- **Set a password** on first run.  
- **Add tasks** with as much or as little detail as you want.
- **Select and edit** tasks easily.
- **Mark tasks as 100% complete** to auto-move them to Completed tab.
- **Delete** single or multiple tasks anytime.
- **Save Updates** at any time to store all your changes securely on disk.
- **Tasks are always stored locally and encrypted.**

***

## 📎 File Storage Details

By default, all data is saved (encrypted) to:
```
C:\\Users\\YourUsername\\.todoapp\\config.json
```
If you change your password, existing data is re-encrypted, so only you can access it.

***

## ❓ FAQ

- **Q:** Is my data ever sent online?
- 
  **A:** Never. All data is local, encrypted, and stored on your device.
- **Q:** Can I reset my password if forgotten?
- 
  **A:** No. To preserve security, only the correct password can unlock your tasks.

***

## 👏 Credits

Made with ❤️ using PyQt5, by [ChayScripts](https://github.com/ChayScripts)

***

## 📄 License

MIT License (see [LICENSE](LICENSE) file for details)
