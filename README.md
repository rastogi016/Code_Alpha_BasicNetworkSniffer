# **Network Sniffer Tool**
This Python-based tool captures network traffic, analyzes packets, and displays details such as source and destination IP addresses and protocols used (TCP or UDP).

## **Features**
  - Captures incoming and outgoing network packets.
  - Extracts and displays:
  - Source IP address
  - Destination IP address
  - Protocol type (TCP or UDP)
  - Real-time packet monitoring.
  - User-friendly display format for packet information.
  
## **How It Works**
  1. Socket Binding:
      The tool binds a raw socket to capture all incoming traffic on the system.
  
  2. Packet Analysis:
      Captured packets are parsed to extract header information such as source and destination IP addresses and the protocol type**
  3. Protocol Identification:
    The tool distinguishes between TCP and UDP packets, displaying relevant information.

## **Usage Instructions**
  **Run the script as root or with appropriate privileges:**
  Ex. sudo python3 network_sniffer_tool.py
  
**Monitor captured packets:**
  The tool will print packet information in real-time.

### **Stop the sniffer**:
  Use Ctrl + C to stop the tool gracefully.

## **Dependencies**
  - Python 3.x
  - Socket module (included by default in Python)
  
**Note**
  - This tool is for educational and ethical purposes only. Unauthorized network monitoring is     illegal and against cybersecurity ethics.
  - Ensure you have permission before using this tool on any network.
    
**Happy Sniffing! 🕵️**
  
