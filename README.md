📡 Packet Sniffer in Python
⚠️ Educational Use Only — Do Not Use Without Proper Authorization

This project is a basic packet sniffer written in Python using the scapy library. It captures and analyzes real-time network traffic, displaying important packet details such as:

Source IP

Destination IP

Protocol used

Payload data (truncated)

🔍 Features
🧾 Real-time packet sniffing

🌐 Shows IP headers and protocol types

📦 Displays a portion of payload (non-binary)

📊 Lightweight and easy to use

🛠️ Requirements
Python 3

Scapy library

Install Scapy:

bash
Copy
Edit
pip install scapy
⚙️ How It Works
The tool uses scapy.sniff() to monitor live packets from the network interface and extract:

Source and destination IP addresses

Protocol (TCP, UDP, ICMP, etc.)

Packet summary and partial payload (if textual)

It uses:

python
Copy
Edit
from scapy.all import sniff, IP
To process and print packet data in real-time.

🧪 Example Output
yaml
Copy
Edit
[+] Packet Captured:
    Source IP: 192.168.1.5
    Destination IP: 172.217.10.46
    Protocol: TCP
    Payload: GET / HTTP/1.1...
💻 How to Run (on Windows)
Open Command Prompt as Administrator

Clone the repo or navigate to the project folder.

Run the script:

bash
Copy
Edit
python packet_sniffer.py
Press Ctrl + C to stop.

⚠️ You must install Npcap or WinPcap for low-level packet capture on Windows:
👉 https://nmap.org/npcap/

⚠️ Legal & Ethical Disclaimer
This packet sniffer is developed for educational purposes only.

Do not run this on networks you don't own or have permission to monitor.

Unauthorized packet sniffing can be illegal under cyber laws and is a breach of privacy.

📁 File Structure
Copy
Edit
packet-sniffer/
├── packet_sniffer.py
└── README.md
👨‍💻 Author
Jeetu Yadav
BTech CSE 
