# Network Rule Engine 🔒

A Windows-based Network Rule Engine built with **C++/CLI and Windows Forms**, designed to monitor, manage, and analyze network traffic through a customizable rule system and real-time packet capture.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [OOP Design](#oop-design)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Screenshots](#screenshots)
- [Dependencies](#dependencies)
- [Limitations](#limitations)
- [Future Improvements](#future-improvements)

---

## Overview

The Network Rule Engine provides an intuitive GUI that allows users — administrators or developers — to define, manage, and apply custom rules for monitoring and controlling network traffic. It combines real-time packet capture with rule-based evaluation and secure logging.

**Built for:** Educational, research, and small-scale administrative use.  
**Platform:** Windows (C++/CLI, .NET Windows Forms)  
**Language:** C++/CLI

---

## Features

### Rules Management
- Create, view, edit, and remove network rules
- Support for both built-in default rules and user-defined rules
- Rules can match on: Source/Destination IP, Ports, Protocol, Action (ALLOW / DENY / LOG), and Priority
- **Time-based rules** — active only during specified hours (e.g., allow FTP only during business hours)
- Import/export rules in `.CSV`, `.LOG`, and encrypted `.DAT` formats

### Packet Capture
- Lists all available network interfaces for selection
- Captures a configurable number of live packets
- Each packet is automatically evaluated against active rules
- Background-threaded capture keeps the GUI fully responsive
- Optional log encryption using a user-supplied key

### Packet Analysis
- Load and analyze previously captured packet data from `.CSV`, `.LOG`, or `.DAT` files
- Evaluates packets against the current rule set
- Displays results in the GUI

### System Logging
- Logs all significant system events: rule changes, capture events, errors
- View, clear, and save logs for auditing or troubleshooting

### Security
- File encryption/decryption via `BasicFileEncryptor`
- Encryption key prompted at runtime — never stored or hardcoded
- Input validation, duplicate rule ID checks, and null safety throughout
- Administrative privilege detection for network interface access

---

## OOP Design

The project applies core OOP principles throughout:

| Concept | Implementation |
|---|---|
| **Classes & Objects** | `Rule`, `TimeBasedRule`, `Packet`, `RuleEngine`, `NetworkPacketCapture`, `MainForm` |
| **Inheritance** | `TimeBasedRule` extends `Rule` with time-window logic |
| **Polymorphism** | Virtual methods `matches()`, `display()`, `toCsvString()` overridden in subclasses |
| **Encapsulation** | Private fields with public getters/setters in all core classes |
| **Abstraction** | `MainForm` exposes a clean UI over complex backend logic |

---

## Project Structure

```
NetworkRuleEngine/
├── MainForm.h / .cpp           # GUI controller and event logic
├── Rule.h / .cpp               # Base rule class
├── TimeBasedRule.h / .cpp      # Time-constrained rule extension
├── RuleEngine.h / .cpp         # Rule storage and evaluation engine
├── Packet.h / .cpp             # Network packet model
├── NetworkPacketCapture.h/.cpp # Device enumeration and live capture
├── BasicFileEncryptor.h / .cpp # File encryption and decryption
└── sample_rules.csv            # Sample rule file for testing
```

---

## Getting Started

### Prerequisites

- Windows OS
- Visual Studio (with C++/CLI support)
- [Npcap](https://npcap.com/) or [WinPcap](https://www.winpcap.org/) installed for packet capture
- .NET Framework (Windows Forms)
- Administrator privileges (required for network device access)

### Build

1. Clone the repository:
   ```bash
   git clone https://github.com/AfanTariq/Network-Rule-Engine.git
   ```
2. Open the solution in Visual Studio.
3. Build in **Release** or **Debug** mode.
4. Run as Administrator.

---

## Usage

### Rules Tab
1. View built-in default rules in the read-only grid.
2. Add custom rules using **Add Rule**, fill in the fields, and hit **Save Rules**.
3. Load existing rule files via **Load Rules** (supports `.csv`, `.log`, `.dat`).

### Packet Capture Tab
1. Click **Refresh Network Devices** to populate the device list.
2. Select a network interface from the dropdown.
3. Set the number of packets to capture.
4. (Optional) Check **Encrypt Logs** and enter an encryption key.
5. Click **Start Capture** — results appear in real time.

### Packet Analysis Tab
1. Click **Browse** to select a packet data file.
2. Click **Analyze File** to evaluate packets against your current rules.
3. Results are displayed in the analysis panel.

### System Logs Tab
- View all timestamped system events.
- Use **Clear Logs** to reset, or **Save Logs** to export for auditing.

---

## Screenshots

> <img width="1218" height="705" alt="image" src="https://github.com/user-attachments/assets/b5bb8834-df64-4e0a-955e-befd5cde6a32" />

> <img width="1208" height="706" alt="image" src="https://github.com/user-attachments/assets/b6587ec0-6d8e-4bd1-a9cc-b31a1346f922" />

> <img width="1212" height="715" alt="image" src="https://github.com/user-attachments/assets/3d1e90c8-b20f-418e-b701-57a908dcc937" /> 

> <img width="1228" height="739" alt="image" src="https://github.com/user-attachments/assets/01bca5b4-29fa-4b0e-9c34-844318fa570a" />

> <img width="1226" height="706" alt="image" src="https://github.com/user-attachments/assets/b6adb656-4f38-4e63-8aed-b1dcbf6e425a" />


| Tab | Description |
|---|---|
| Rules Management | Default and user-defined rules displayed in separate grids |
| Packet Capture | Network device selection and live capture log |
| Packet Analysis | File-based packet evaluation results |
| System Logs | Timestamped event history |

---

## Dependencies

| Library | Purpose |
|---|---|
| WinPcap / Npcap | Low-level packet capture and device enumeration |
| System.Windows.Forms | GUI components |
| System.Threading | Background packet capture thread |
| System::IO | String conversion between .NET and C++ |
| Microsoft::VisualBasic | User prompts (e.g., encryption key input) |
| msclr/marshal | Interop between `System::String^` and `std::string` |

---

## Limitations

- Packet capture requires **administrator privileges** and compatible network drivers.
- No deep packet inspection or Layer 7 (application-layer) filtering.
- Encryption is basic — not suitable for production or enterprise-grade security.
- Optimized for moderate traffic; may degrade under high-throughput conditions.
- No built-in user authentication or role-based access control.

---

## Future Improvements

- Advanced rule types with protocol-specific attributes and custom scripting
- Industry-standard encryption (AES-256) and user authentication
- Parallel rule evaluation and caching for better performance
- Automated rule conflict detection and visualization
- Traffic dashboards with charts for pattern analysis
- Cross-platform support or web-based interface

---

## Author

**Muhammad Afan Tariq**  
Department of Cyber Security  
Air University Islamabad 2025
