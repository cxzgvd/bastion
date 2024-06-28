# Bastion

Bastion is a command-line tool designed to secure a Linux server by automating the installation and configuration of various security-related services. It provides a user-friendly interface for beginners and experienced users alike, offering menus and prompts to streamline the setup process.

## Features

Bastion includes a comprehensive set of modules categorized into different sections:

### System and Services
1. System update
2. System upgrade
3. Installation and configuration SSH
4. Installation and configuration FTP
5. Installation and configuration SMB
6. Installation and configuration MySQL
7. Installation and configuration Apache
8. Installation and configuration OpenVPN
9. Installation and configuration Fail2Ban
10. Installation and configuration UFW
11. Installation and configuration ClamAV

### Network Tools
21. ARP-spoof Detection
22. TCP Connector
23. Wifi Attacks Detector
24. TCP Listener
25. Port Scanner
26. Banner Grabber

### Analysis, Forensic, OSINT and Threat Hunting
31. File Analyzer
32. PCAP Analyzer
33. Redirect Checker
34. WHOIS Domain Information
35. IP Reputation (VirusTotal) - needs API key
36. Domain Reputation (VirusTotal) - needs API key
37. File Reputation by Hash (VirusTotal) - needs API key
38. HaveIBeenPwned Email Leak - needs API key
39. Suspicious Email Check - needs API key
40. Get File Hashes
41. Analyze SSL Certificates
42. Hash Identifier
43. Check If The Website is online

### Active Monitoring and Responding
61. Get System Info
62. List Active Users
63. List Open Network Connections
64. Monitor Processes
65. Terminate Process
66. CPU and RAM usage monitor
67. Reverse/Bind Shell Connection Detector

### Reporting and Other Tools
81. Report Generator
82. Take A Screenshot
84. Useful Links And Resources

### Config and Credits
96. Advanced Security Configuration
97. Install Security Tools
98. Info And Contact
99. Configure
0. Exit

## Installation

To use Bastion, follow these steps:

### Prerequisites

- Python 3.x installed
- Pip package manager installed
- Access to run commands as root (sudo privileges)

### Steps

1. **Clone the repository:**

   ```bash
   git clone https://github.com/cxzgvd/bastion.git
   cd bastion
2. **Install Python dependencies:**

   sudo pip install -r requirements.txt

3.**Run the program**

  sudo python bastion.py

  Ensure to run the program with sudo or as root to enable all functionalities that require elevated privileges.

### Usage
Navigate the menus using the numeric options provided.
Follow the on-screen prompts to configure and execute various security tasks.
Refer to module descriptions for detailed functionalities.
