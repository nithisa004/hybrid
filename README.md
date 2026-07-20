# 🛡️ Hybrid SIEM – Real-Time Threat Detection and Response System

## 📌 Overview

Hybrid SIEM is a Security Information and Event Management (SIEM) system developed to monitor Windows security events and network activity in real time. It collects security logs, detects suspicious activities using rule-based detection, generates alerts, automatically blocks malicious IP addresses through the Windows Firewall, sends email notifications, and provides a web-based dashboard for security monitoring.

This project demonstrates the core functionality of a modern SIEM platform and serves as a foundation for future AI/ML-based threat detection.

---

# ✨ Features

* 🔍 Real-time Windows Event Log Monitoring
* 🌐 Network Activity Monitoring
* 🚨 Rule-Based Threat Detection
* 📧 Email Alert Notifications
* 🔥 Firewall IP Blocking
* 📊 Interactive Security Dashboard
* 📈 Weekly Security Report Generation
* 🧪 Attack Simulation Module
* 🔄 Real-time Alert Updates
* 🌍 REST API using Django

---

# 🛠️ Technology Stack

### Backend

* Python
* Django
* Django REST Framework

### Frontend

* Ionic
* Angular

### Database

* SQLite

### Security

* Windows Event Logs
* PowerShell
* Windows Firewall

### Tools

* Git
* GitHub
* Visual Studio Code

# 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/nithisa004/hybrid.git
```

Move into the project directory:

```bash
cd hybrid
```

Run the setup script:

```powershell
.\setup_project.bat
```

---

# ▶️ Running the Project

## Terminal 1 – Backend

```powershell
cd backend
py manage.py runserver
```

---

## Terminal 2 – Frontend

```powershell
cd frontend
ionic serve
```

---

## Terminal 3 – Detection Engine (Run as Administrator)

```powershell
cd detection
py realtime_detection.py
```

or

```powershell
cd detection
python realtime_detection.py
```

---

# 🧪 Attack Simulation

Use the following commands to simulate attacks and test the detection engine.

| Command                              | Description                       |
| ------------------------------------ | --------------------------------- |
| `py simulate_attacks.py bruteforce`  | Simulate Brute Force Login Attack |
| `py simulate_attacks.py dos`         | Simulate DoS Attack               |
| `py simulate_attacks.py logclear`    | Simulate Security Log Clearing    |
| `py simulate_attacks.py persistence` | Simulate Malware Persistence      |
| `py simulate_attacks.py rdp`         | Simulate RDP Activity             |
| `py simulate_attacks.py driver`      | Simulate Driver Blocking          |
| `py simulate_attacks.py`             | Run All Attack Simulations        |

---

# 🌐 Network Testing

From Kali Linux:

```bash
ping 192.168.56.1
```

```bash
nmap -sS 192.168.56.1
```

---

# 🔥 Firewall Management

View firewall rules:

```powershell
netsh advfirewall firewall show rule name=all | findstr HybridSIEM
```

Remove Hybrid SIEM firewall rules:

```powershell
Get-NetFirewallRule -DisplayName "HybridSIEM_Block_*" | Remove-NetFirewallRule
```

Verify removal:

```powershell
netsh advfirewall firewall show rule name=all | findstr HybridSIEM
```

---

# 📸 Screenshots

Add screenshots of:

* Dashboard
* Threat Detection Alerts
* Email Notifications
* Firewall Blocking
* Weekly Reports
* Attack Simulation Results

---

# 📊 Project Status

**Status:** ✅ Completed

The project has been successfully developed and tested with the following capabilities:

* Real-time Windows Event Log Monitoring
* Rule-Based Threat Detection
* Email Alert Generation
* Automatic Firewall IP Blocking
* Interactive Dashboard
* REST API Integration
* Weekly Security Report Generation
* Attack Simulation and Validation

---

# 🚀 Future Enhancements

The current version uses a rule-based detection engine. Future releases will include advanced capabilities such as:

* 🤖 Machine Learning–based Threat Detection
* 🧠 Autoencoder-based Anomaly Detection
* 🌳 XGBoost-based Attack Classification

---

# 📄 License

This project is provided for educational and research purposes.

---

# ⚠️ Disclaimer

This project is intended for educational purposes and authorized cybersecurity research only. The attack simulation scripts must be used only in controlled environments or systems where you have explicit permission.

---

# 👩‍💻 Author

**Nithisa Devi J**

Cyber Security Trainer | Python Developer | Security Enthusiast

GitHub: https://github.com/nithisa004
