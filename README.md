# 🔍 pySniff — Basic Network Sniffer

**pySniff** is a Python-based network packet sniffer built with **Scapy**. It captures and analyzes live network traffic, monitors common network protocols, detects potential plaintext credentials, extracts DNS queries, and can save packet captures for further analysis in **Wireshark**.

> ⚠️ **Legal & Ethical Use:** pySniff is intended for educational purposes and authorized security testing only. Use this tool only on networks and systems you own or have explicit permission to monitor.

---

## 🚀 Features

* ✅ Live network packet capture
* ✅ TCP, UDP, and ICMP traffic analysis
* ✅ BPF filter support
* ✅ Plaintext credential detection

  * HTTP
  * FTP
  * Telnet
  * SMTP AUTH
* ✅ DNS query extraction and logging
* ✅ ASCII and hexadecimal payload inspection
* ✅ Save packet captures as `.pcap`
* ✅ Wireshark-compatible capture files
* ✅ Packet statistics by protocol
* ✅ Automatic network interface detection
* ✅ Network interface listing
* ✅ Packet count limit
* ✅ Capture timeout support
* ✅ Verbose packet inspection

---

## 🛠️ Requirements

Before installing pySniff, make sure you have:

* **Python 3.8+**
* **Scapy**
* Linux, macOS, or Windows
* **Npcap** on Windows
* Root/Administrator privileges for packet capture

Linux provides the best support for raw packet capture.

---

## 📥 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Ahmiiii250/CodeAlpha_Basic-Network-Sniffer.git
```

### 2. Enter the Project Directory

```bash
cd CodeAlpha_Basic-Network-Sniffer
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

### List Available Network Interfaces

```bash
sudo python3 pysniff.py --list-interfaces
```

### Start Sniffing on an Interface

```bash
sudo python3 pysniff.py -i eth0
```

### Capture HTTP Traffic

```bash
sudo python3 pysniff.py -f "tcp port 80"
```

### Capture DNS Traffic

```bash
sudo python3 pysniff.py -f "udp port 53"
```

### Capture DNS Traffic with Payload Inspection

```bash
sudo python3 pysniff.py -f "udp port 53" -v
```

### Capture a Specific Number of Packets

```bash
sudo python3 pysniff.py -c 100
```

### Save Captured Packets to PCAP

```bash
sudo python3 pysniff.py -c 100 -w capture.pcap
```

The generated `.pcap` file can be opened and analyzed using **Wireshark**.

### Stop Capture After a Specific Time

```bash
sudo python3 pysniff.py -t 60
```

---

## ⚙️ Command-Line Options

| Option              | Description                                    |
| ------------------- | ---------------------------------------------- |
| `-i, --iface`       | Network interface to capture from              |
| `-f, --filter`      | BPF packet capture filter                      |
| `-c, --count`       | Number of packets to capture (`0` = unlimited) |
| `-t, --timeout`     | Stop capture after N seconds                   |
| `-w, --write`       | Save captured packets to a PCAP file           |
| `-v, --verbose`     | Display packet payload information             |
| `--list-interfaces` | Display available network interfaces           |

---

## 🔎 BPF Filter Examples

pySniff supports **Berkeley Packet Filter (BPF)** expressions.

### HTTP

```bash
sudo python3 pysniff.py -f "tcp port 80"
```

### HTTPS

```bash
sudo python3 pysniff.py -f "tcp port 443"
```

### DNS

```bash
sudo python3 pysniff.py -f "udp port 53"
```

### Specific Host

```bash
sudo python3 pysniff.py -f "host 192.168.1.10"
```

### TCP Traffic

```bash
sudo python3 pysniff.py -f "tcp"
```

### UDP Traffic

```bash
sudo python3 pysniff.py -f "udp"
```

---

## 📊 Example Output

```text
[12:04:31.221] 192.168.1.10:52411 -> 93.184.216.34:80 [TCP] S (74 bytes)

[12:04:31.412] 192.168.1.10:52412 -> 192.168.1.1:53 [UDP] (78 bytes)
    DNS Query: example.com
```

### Potential Credential Detection

```text
[***] POTENTIAL CREDENTIAL DETECTED [***]

    Flow    : 192.168.1.10:52413 -> 93.184.216.34:80
    Match   : user, pass
    Data    : POST /login HTTP/1.1 ...
              username=admin&password=...

[***]****************************************[***]
```

> **Note:** Credential detection identifies potential plaintext credential patterns in captured traffic. It should not be treated as proof that valid credentials were exposed.

---

## 🖥️ Wireshark Analysis

Captured packets can be saved using:

```bash
sudo python3 pysniff.py -w capture.pcap
```

Then open the generated file in **Wireshark** for deeper packet-level analysis.

You can inspect:

* Source and destination IPs
* TCP/UDP ports
* DNS requests
* Packet payloads
* Protocol information
* Network conversations
* Packet timing

---

## 📁 Project Structure

```text
CodeAlpha_Basic-Network-Sniffer/
│
├── pysniff.py
├── requirements.txt
├── README.md
└── capture.pcap
```

> `capture.pcap` is an example output file and does not need to be committed to the repository unless required.

---

## 🔐 Security & Privacy

Network sniffing can expose sensitive information such as:

* IP addresses
* DNS queries
* HTTP data
* Unencrypted credentials
* Application traffic

Always obtain permission before capturing network traffic.

**Do not use pySniff to monitor networks, devices, or users without authorization.**

---

## ⚠️ Legal Disclaimer

This project is provided **for educational purposes and authorized penetration testing only**.

The author is not responsible for any misuse, damage, privacy violation, or unauthorized activity performed using this software.

Always obtain appropriate authorization before performing network monitoring or packet capture.

---

## 🎯 Learning Objectives

This project demonstrates practical concepts related to:

* Network packet analysis
* Python networking
* Scapy
* TCP/IP fundamentals
* UDP and ICMP
* DNS traffic analysis
* BPF filtering
* Packet payload inspection
* Network security monitoring
* PCAP analysis
* Wireshark
* Basic credential exposure detection

---

## 👨‍💻 Author

**Ahmiiii250**

GitHub:
https://github.com/Ahmiiii250

---

## ⭐ Support

If you find this project useful for learning **Python, networking, or cybersecurity**, consider giving the repository a ⭐ on GitHub.

**Use responsibly. Learn ethically. Hack legally. 🔐**
