# 🔍 Network Packet Analyzer

A simple, beginner-friendly **Network Packet Analyzer** desktop application built with **Python 3**, **Scapy**, and **Tkinter**. It captures live network traffic and displays key details like source/destination IPs, protocol type, and packet length in a clean, dark-themed GUI.

---

## 📌 Project Overview

This tool sniffs network packets in real time and presents them in a scrollable table. It is designed for **educational purposes** to help beginners understand how network traffic works at the packet level.

---

## ✨ Features

| Feature                | Description                                          |
|------------------------|------------------------------------------------------|
| **Start Capture**      | Begin sniffing network packets in real time          |
| **Stop Capture**       | Halt an ongoing capture session                      |
| **Clear Results**      | Remove all captured packets from the display         |
| **Export Results**      | Save captured packet data to a `.txt` file           |
| **Packet Table**       | Scrollable table showing Timestamp, Source IP, Destination IP, Protocol, and Length |
| **Packet Counter**     | Live count of total packets captured                 |
| **Status Indicator**   | Shows **Ready**, **Capturing…**, or **Stopped**      |
| **Error Handling**     | Graceful messages for missing privileges or dependencies |
| **About Dialog**       | Developer info and contact details                   |

---

## 🛠 Technologies Used

- **Python 3** – Core programming language
- **Scapy** – Packet sniffing and dissection
- **Tkinter** – GUI framework (ships with Python)

---

## 📂 Project Structure

```
Network-Packet-Analyzer/
│
├── main.py              # Main application (GUI + capture logic)
├── requirements.txt     # Python dependencies
├── README.md            # Project documentation (this file)
├── assets/              # Icons and other static assets
└── screenshots/         # Application screenshots
```

---

## ⚙️ Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/<your-username>/Network-Packet-Analyzer.git
cd Network-Packet-Analyzer
```

### 2. Create a Virtual Environment (recommended)

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

> **Note (Windows):** Scapy on Windows also needs [Npcap](https://npcap.com/) installed with *WinPcap API-Compatible Mode* enabled.

---

## 🚀 How to Run

> **Important:** Packet capture requires **administrator / root** privileges.

### Windows

```bash
# Open Command Prompt or PowerShell as Administrator
python main.py
```

### macOS / Linux

```bash
sudo python main.py
```

---

## 📸 Sample Output

When the application launches you will see a dark-themed window:

| #  | Timestamp           | Source IP       | Destination IP  | Protocol | Length |
|----|---------------------|-----------------|-----------------|----------|--------|
| 1  | 2025-07-27 20:30:01 | 192.168.1.5     | 142.250.195.46  | TCP      | 74     |
| 2  | 2025-07-27 20:30:02 | 142.250.195.46  | 192.168.1.5     | TCP      | 66     |
| 3  | 2025-07-27 20:30:03 | 192.168.1.5     | 8.8.8.8         | UDP      | 82     |
| 4  | 2025-07-27 20:30:04 | 8.8.8.8         | 192.168.1.5     | UDP      | 98     |

The status bar at the bottom shows the current state (**Ready / Capturing… / Stopped**) and the total packet count.

---

## 🔮 Future Improvements

- [ ] Add protocol-based filtering (show only TCP, UDP, etc.)
- [ ] Implement a search/filter bar for IPs or protocols
- [ ] Show detailed packet payload on row click
- [ ] Add graphical statistics (packet-per-second chart)
- [ ] Support for saving/loading captures in `.pcap` format
- [ ] Dark/Light theme toggle
- [ ] Network interface selector dropdown

---

## 👤 About

| Field       | Details                                                        |
|-------------|----------------------------------------------------------------|
| **Developer** | Siva Sankar                                                 |
| **Project**   | Network Packet Analyzer                                     |
| **Purpose**   | Educational and cybersecurity learning purposes only         |
| **Contact**   | +91 9666241489                                               |

---

## 📄 License

This project is intended for **educational use only**. Use responsibly and only on networks you have permission to monitor.

---

> _Developed by **Siva Sankar** – Network Packet Analyzer | CodSoft Virtual Internship_
