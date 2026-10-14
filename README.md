# Authorized TCP Port Scanner (Capstone Project)

## 📜 Project Overview
This repository contains `port_scanner.py`, a custom Python tool developed for the Capstone Project security assessment. Designed for use in authorized penetration testing engagements, this script automates the reconnaissance phase by identifying open TCP ports on target systems.

The tool was specifically utilized to assess a legacy development environment (Metasploitable 3) to uncover exposed attack surfaces, outdated services, and potential entry points for privilege escalation or lateral movement.

## ⚠️ Disclaimer & Ethical Use
**This tool is intended for authorized security testing and educational purposes only.**
- **Authorization:** Always obtain explicit written permission from the system owner before scanning.
- **Scope:** Use only within the defined Rules of Engagement (ROE).
- **Impact:** While this scanner uses standard TCP connections, aggressive scanning on production systems may trigger IDS/IPS alerts or cause instability in legacy services.
- **Liability:** The authors are not liable for any misuse, network disruption, or legal issues arising from the use of this script.

## 🛡️ Features
- **Dynamic Port Scanning:** Configable to scan specific ports or ranges (e.g., 1-1024, 1-65535).
- **Socket-Based Detection:** Utilizes Python's `socket` library to perform reliable TCP connection attempts.
- **Threaded Execution:** Implements multithing (`threading`) to parallelize scans, significantly reducing execution time compared to sequential scanning.
- **Clear Reporting:** Outputs a clean, readable list of open ports and associated services (where identifiable).
- **Error Handling:** Robust handling of timeouts, connection refusals, and network errors to ensure script stability.
- **Legal Compliance:** Includes built-in checks and warnings to remind users of authorization requirements.

## 📋 Technical Details
- **Language:** Python 3
- **Libraries:** `socket`, `threading`, `sys`, `datetime`
- **OS Compatibility:** Linux (Kali, Ubuntu), macOS, Windows (with appropriate permissions)
- **Methodology:** TCP Connect Scan (Full Open). This method completes the three-way handshake, making it noisy but reliable and less likely to be blocked by firewalls that drop incomplete packets.

## 🚀 Installation & Requirements
No external libraries are required. This script uses only Python standard libraries.

**Prerequisites:**
- Python 3.6 or higher
- Network access to the target host
- Appropriate permissions (Root/Sudo may be required for certain raw socket operations, though standard TCP connects usually work with user privileges)

## 💻 Usage
Run the script from the command line. You must specify the target IP address and the port range.

### Basic Usage
```bash
python3 port_scanner.py
