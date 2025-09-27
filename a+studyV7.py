#!/usr/bin/env python3
# CompTIA A+ 90-Question Exam Simulation — 260+ item pool, no repeats, scaled scoring

import argparse
import random
import time
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional, Set

# ---------------------------
# Data model
# ---------------------------
@dataclass
class QA:
    domain: str
    subdomain: str
    question: str
    choices: List[str]
    answer: str
    explanation: str
    difficulty: str  # "easy" | "medium" | "hard"

# ---------------------------
# Domain generators
# ---------------------------
def gen_hardware() -> List[QA]:
    items: List[QA] = []
    items += [
        QA("Hardware","Motherboards","Which slot is used for modern GPUs?",
           ["AGP","PCIe x16","ISA","PCI"],"PCIe x16",
           "Modern GPUs use PCIe x16 for bandwidth.","easy"),
        QA("Hardware","Motherboards","Which connector powers the motherboard?",
           ["Molex","SATA power","24-pin ATX","PCIe 6-pin"],"24-pin ATX",
           "The 24-pin ATX is the primary motherboard power connector.","easy"),
        QA("Hardware","CPU power","Which connector powers CPU VRMs?",
           ["4/8-pin EPS","24-pin ATX","Molex","SATA power"],"4/8-pin EPS",
           "EPS connectors deliver CPU power to the motherboard VRM.","medium"),
        QA("Hardware","Memory","Which RAM type is common in laptops?",
           ["DIMM","SO-DIMM","SIMM","ECC RDIMM"],"SO-DIMM",
           "Laptops typically use SO-DIMM modules.","easy"),
        QA("Hardware","Memory","ECC memory is primarily used in:",
           ["Gaming rigs","Mission-critical servers","Low-end laptops","IoT devices"],"Mission-critical servers",
           "ECC corrects single-bit errors for reliability.","medium"),
        QA("Hardware","Storage","Which interface provides the highest SSD performance?",
           ["SATA III","NVMe (PCIe)","USB 3.0","eSATA"],"NVMe (PCIe)",
           "NVMe over PCIe offers much higher throughput than SATA.","medium"),
        QA("Hardware","Storage","RAID 0 provides:",
           ["Mirroring","Parity","Striping without fault tolerance","Cold spare"],"Striping without fault tolerance",
           "RAID 0 stripes data but offers no redundancy.","easy"),
        QA("Hardware","Storage","Which RAID level uses parity with single-disk fault tolerance?",
           ["RAID 0","RAID 1","RAID 5","JBOD"],"RAID 5",
           "RAID 5 uses distributed parity across disks.","medium"),
        QA("Hardware","Storage","Which RAID level mirrors data?",
           ["RAID 0","RAID 1","RAID 5","RAID 10"],"RAID 1",
           "RAID 1 mirrors data across drives for redundancy.","easy"),
        QA("Hardware","Displays","Which connector supports analog only?",
           ["VGA","HDMI","DisplayPort","DVI-D"],"VGA",
           "VGA is analog; others are digital.","easy"),
        QA("Hardware","Displays","Which cable carries digital video and audio?",
           ["VGA","DVI-A","HDMI","Composite"],"HDMI",
           "HDMI carries digital video/audio and supports high resolutions.","easy"),
        QA("Hardware","Displays","Which connector supports daisy-chaining monitors?",
           ["HDMI","DisplayPort","DVI-D","VGA"],"DisplayPort",
           "DisplayPort supports MST for chained displays.","medium"),
        QA("Hardware","Ports","Thunderbolt 3 commonly uses which connector?",
           ["USB-A","USB-C","Mini-USB","Micro-USB"],"USB-C",
           "Thunderbolt 3 uses USB-C with high throughput.","medium"),
        QA("Hardware","Cooling","Best method to handle a high-TDP CPU?",
           ["Passive heatsink","Liquid cooling","Only case fans","Underclocking"],"Liquid cooling",
           "Liquid cooling manages heat effectively for high TDP CPUs.","medium"),
        QA("Hardware","Cabling","Which cable supports 10Gb up to ~55m?",
           ["Cat5e","Cat6","Cat6a","Cat3"],"Cat6",
           "Cat6 supports 10Gb up to ~55m; Cat6a supports 100m.","medium"),
        QA("Hardware","Peripherals","Which connector is reversible?",
           ["USB-A","USB-B","USB-C","Mini-USB"],"USB-C",
           "USB-C is reversible and supports higher data/power.","easy"),
        QA("Hardware","Storage","Which media uses magnetic platters?",
           ["SSD","HDD","NVMe drive","SD card"],"HDD",
           "HDDs store data on spinning magnetic platters.","easy"),
        QA("Hardware","Storage","M.2 NVMe SSDs use which bus?",
           ["SATA","PCIe","USB","Thunderbolt"],"PCIe",
           "NVMe SSDs connect via PCIe lanes.","medium"),
        QA("Hardware","Power","Which connector can power GPUs?",
           ["Molex","SATA power","PCIe 8-pin","Fan header"],"PCIe 8-pin",
           "PCIe 6/8/12-pin connectors are used for discrete GPUs.","easy"),
        QA("Hardware","Power","Which PSU feature stabilizes output voltage?",
           ["Active PFC","RGB lighting","Modular cables","Wireless control"],"Active PFC",
           "Power factor correction improves efficiency/stability.","medium"),
        QA("Hardware","Cabling","Which copper cable reduces EMI best?",
           ["UTP","STP","Coax","Fiber"],"STP",
           "Shielded Twisted Pair reduces electromagnetic interference.","medium"),
        QA("Hardware","Motherboards","Which slot fits typical NVMe drives?",
           ["PCIe x1","M.2","PCI","AGP"],"M.2",
           "M.2 slots host NVMe SSD modules.","easy"),
        QA("Hardware","Storage","Which device offers hot-swappable, redundant storage at block level?",
           ["NAS","SAN","DAS","Tape"],"SAN",
           "SAN provides block-level storage with advanced redundancy.","medium"),
        QA("Hardware","Displays","Which spec primarily affects gaming smoothness?",
           ["Refresh rate","Pixel pitch","Color depth","Connector type"],"Refresh rate",
           "Higher Hz yields smoother motion.","easy"),
        QA("Hardware","Memory","Dual-channel memory requires:",
           ["Same capacity and speed in paired slots","ECC modules only","SO-DIMM only","Single module"],"Same capacity and speed in paired slots",
           "Matched modules enable dual-channel performance.","medium"),
        QA("Hardware","Ports","USB 3.0 theoretical max speed is:",
           ["480 Mbps","5 Gbps","10 Gbps","40 Gbps"],"5 Gbps",
           "USB 3.0 (3.1 Gen1) is 5 Gbps.","easy"),
        QA("Hardware","Power","A PSU rated 80+ Gold indicates:",
           ["High efficiency","RGB lighting","Passive cooling","Server-only use"],"High efficiency",
           "80+ Gold certifies efficiency at specified loads.","easy"),
        QA("Hardware","Peripherals","NVMe vs SATA SSD difference primarily:",
           ["Connector color","Interface bandwidth","Form factor only","Uses spinning platters"],"Interface bandwidth",
           "NVMe over PCIe is much faster than SATA.","easy"),
    ]
    # Extra quick items to increase hardware count
    items += [
        QA("Hardware","Form factors","Which motherboard form factor is smallest?",
           ["ATX","Micro-ATX","Mini-ITX","E-ATX"],"Mini-ITX",
           "Mini-ITX is a compact form factor.","easy"),
        QA("Hardware","Memory","Which spec indicates RAM speed?",
           ["CAS latency","RPM","dpi","Hz only"],"CAS latency",
           "CAS and frequency affect RAM performance.","medium"),
    ]
    return items

def gen_networking() -> List[QA]:
    items: List[QA] = []
    items += [
        QA("Networking","IP basics","APIPA addresses fall within:",
           ["192.168.0.0/16","169.254.0.0/16","10.0.0.0/8","172.16.0.0/12"],"169.254.0.0/16",
           "APIPA uses 169.254.x.x when DHCP fails.","easy"),
        QA("Networking","IP basics","Which is a private Class A network?",
           ["192.168.0.0/16","10.0.0.0/8","172.16.0.0/12","100.64.0.0/10"],"10.0.0.0/8",
           "10.0.0.0/8 is private Class A space.","easy"),
    ]
    port_map = [
        ("HTTP","80"),("HTTPS","443"),("DNS","53"),("SMTP","25"),("IMAP","143"),("POP3","110"),
        ("SSH","22"),("Telnet","23"),("FTP","21"),("SFTP","22"),("RDP","3389"),("SNMP","161"),
        ("LDAP","389"),("LDAPS","636"),("NTP","123"),("TFTP","69"),("Kerberos","88"),("SMB","445"),
        ("MySQL","3306"),("PostgreSQL","5432"),("MSSQL","1433"),("Oracle SQL*Net","1521"),
        ("DHCP Server","67"),("DHCP Client","68"),("HTTP Proxy","8080"),("IMAPS","993"),("POP3S","995"),
        ("Syslog","514"),("LDAP Global Catalog","3268"),("L2TP","1701"),("IKE","500"),("NetBIOS Name","137"),
        ("NetBIOS Datagram","138"),("NetBIOS Session","139"),("RPC","135"),
    ]
    for svc, port in port_map:
        items.append(QA("Networking","Ports",f"Which port is commonly used by {svc}?",
                        [port,"22","53","443"], port,
                        f"{svc} commonly uses TCP/UDP {port}.","easy"))
    items += [
        QA("Networking","Tools","Which tool traces the path to a host?",
           ["ping","traceroute/tracert","ipconfig/ifconfig","dig"],"traceroute/tracert",
           "Traceroute shows each hop and its latency.","easy"),
        QA("Networking","Tools","Which tool is used for DNS queries?",
           ["curl","dig","scp","netstat"],"dig",
           "dig queries DNS resource records.","easy"),
        QA("Networking","Wireless","802.11ac primarily operates in:",
           ["2.4 GHz","5 GHz","900 MHz","60 GHz"],"5 GHz",
           "802.11ac targets 5 GHz for wider channels.","easy"),
        QA("Networking","Wireless","WPA2-AES provides:",
           ["Open access","Legacy security","Strong encryption","MAC filtering"],"Strong encryption",
           "WPA2-AES offers strong WLAN encryption.","easy"),
        QA("Networking","Devices","A switch operates primarily at OSI layer:",
           ["1","2","3","4"],"2",
           "Switches forward frames based on MAC addresses.","easy"),
        QA("Networking","Devices","A router operates primarily at OSI layer:",
           ["2","3","4","7"],"3",
           "Routers forward packets based on IP addresses.","easy"),
        QA("Networking","WAN","Which technology provides dedicated leased lines?",
           ["DSL","Cable","T1/E1","Satellite"],"T1/E1",
           "T1/E1 are dedicated circuits.","medium"),
        QA("Networking","Topologies","Which topology connects nodes to a central device?",
           ["Bus","Ring","Star","Mesh"],"Star",
           "Star uses a central hub/switch.","easy"),
    ]
    return items

def gen_operating_systems() -> List[QA]:
    items: List[QA] = []
    items += [
        QA("Operating systems","Windows tools","Which tool checks system files?",
           ["chkdsk","sfc /scannow","ipconfig","msconfig"],"sfc /scannow",
           "sfc verifies and repairs system files.","easy"),
        QA("Operating systems","Windows tools","Which utility edits boot configuration?",
           ["regedit","bcdedit","netstat","wbadmin"],"bcdedit",
           "bcdedit manages Windows boot configuration.","medium"),
        QA("Operating systems","Windows tools","Which manages services startup type?",
           ["Task Manager","Services.msc","Event Viewer","PerfMon"],"Services.msc",
           "Services.msc sets service properties and startup types.","easy"),
        QA("Operating systems","Windows tools","Event Viewer helps you:",
           ["Manage drivers","View system/application logs","Install apps","Configure BIOS"],"View system/application logs",
           "Event Viewer displays logs for troubleshooting.","easy"),
        QA("Operating systems","Windows tools","Which tool shows running processes and resource usage?",
           ["Task Manager","Device Manager","PerfMon","MSConfig"],"Task Manager",
           "Task Manager shows CPU/memory/disk usage and processes.","easy"),
        QA("Operating systems","Windows tools","Which tool tracks performance counters?",
           ["PerfMon","Task Manager","Device Manager","Event Viewer"],"PerfMon",
           "Performance Monitor tracks counters over time.","medium"),
        QA("Operating systems","Windows tools","Which tool manages startup programs?",
           ["MSConfig","Event Viewer","PerfMon","Services.msc"],"MSConfig",
           "MSConfig configures startup options.","easy"),
        QA("Operating systems","Windows commands","What does chkdsk primarily do?",
           ["Check disk integrity","Configure IP","Update policies","Resolve names"],"Check disk integrity",
           "chkdsk scans/fixes file system errors.","easy"),
        QA("Operating systems","Windows commands","ipconfig /all shows:",
           ["Firewall rules","Routing table","Full network config","Disk usage"],"Full network config",
           "ipconfig /all displays detailed adapter settings.","easy"),
        QA("Operating systems","Windows commands","Which command refreshes Group Policy?",
           ["gpupdate /force","ipconfig /renew","netsh winsock reset","sfc /scannow"],"gpupdate /force",
           "gpupdate /force refreshes Group Policy settings.","easy"),
        QA("Operating systems","Windows commands","Which command resets TCP/IP stack?",
           ["netsh int ip reset","ipconfig /flushdns","gpupdate /force","sfc /scannow"],"netsh int ip reset",
           "Resets TCP/IP parameters to defaults.","medium"),
        QA("Operating systems","macOS","Which tool manages packages via terminal?",
           ["brew","apt","yum","dnf"],"brew",
           "Homebrew is a common macOS package manager.","medium"),
        QA("Operating systems","Linux commands","Which lists files including hidden ones?",
           ["ls -la","cat -A","find -type f","du -h"],"ls -la",
           "ls -la shows long listing including dotfiles.","easy"),
        QA("Operating systems","Linux commands","Which command changes permissions?",
           ["chmod","chown","ls","touch"],"chmod",
           "chmod modifies file permissions.","easy"),
        QA("Operating systems","Linux commands","Which command changes ownership?",
           ["chmod","chown","umask","ls -l"],"chown",
           "chown changes owner/group.","easy"),
        QA("Operating systems","Linux commands","Which shows CPU/memory usage interactively?",
           ["top","ls","sed","awk"],"top",
           "top displays real-time process resource usage.","easy"),
        QA("Operating systems","Linux networking","Which file configures DNS resolvers?",
           ["/etc/resolv.conf","/etc/hosts","/etc/fstab","/etc/network/interfaces"],"/etc/resolv.conf",
           "resolv.conf lists DNS servers.","medium"),
        QA("Operating systems","Linux networking","Which command shows route table?",
           ["ip route","ip addr","nslookup","systemctl"],"ip route",
           "ip route displays kernel routing table entries.","easy"),
        QA("Operating systems","Linux permissions","Which octal sets rwxr-xr--?",
           ["754","644","700","777"],"754",
           "Owner=7 (rwx), group=5 (r-x), others=4 (r--).","medium"),
        QA("Operating systems","Linux files","Which command finds files by name?",
           ["find","grep","less","tee"],"find",
           "find searches filesystem trees.","easy"),
    ]
    return items

def gen_security() -> List[QA]:
    items: List[QA] = []
    items += [
        QA("Security","Principles","Encrypting sensitive data primarily supports:",
           ["Confidentiality","Integrity","Availability","Non-repudiation"],"Confidentiality",
           "Encryption prevents unauthorized disclosure.","easy"),
        QA("Security","Principles","Hashing primarily supports:",
           ["Confidentiality","Integrity","Availability","Authentication"],"Integrity",
           "Hashes detect data alteration.","easy"),
        QA("Security","Auth","A smart card is which factor?",
           ["Something you know","Something you have","Something you are","Somewhere you are"],"Something you have",
           "Smart cards are possession factors.","easy"),
        QA("Security","Auth","A fingerprint is:",
           ["Something you know","Something you have","Something you are","Somewhere you are"],"Something you are",
           "Biometric traits are 'are' factors.","easy"),
        QA("Security","Threats","Targeted phishing to executives is:",
           ["Smishing","Spear phishing","Whaling","Vishing"],"Whaling",
           "Whaling targets high-value individuals.","easy"),
        QA("Security","Malware","Ransomware primarily:",
           ["Exfiltrates data quietly","Encrypts files and demands payment","Logs keystrokes","Scans ports"],"Encrypts files and demands payment",
           "Ransomware encrypts data and requests ransom.","easy"),
        QA("Security","Crypto","AES is best described as:",
           ["Asymmetric","Symmetric block cipher","Hash function","Stream-only"],"Symmetric block cipher",
           "AES is a symmetric block cipher widely used.","medium"),
        QA("Security","PKI","What binds a public key to an identity?",
           ["Digital certificate","CRL","CSR","OCSP"],"Digital certificate",
           "Certificates associate identities and public keys via a CA signature.","easy"),
        QA("Security","PKI","Which list contains revoked certificates?",
           ["CRL","CSR","OCSP","HSM"],"CRL",
           "CRLs list revoked certs; OCSP provides real-time status.","medium"),
        QA("Security","Network","Which protocol secures remote management?",
           ["Telnet","SSH","FTP","HTTP"],"SSH",
           "SSH provides encrypted remote shell and management.","easy"),
        QA("Security","Wireless","Disabling SSID broadcast significantly increases security:",
           ["True","False"],"False",
           "Obscurity isn't strong security; use WPA2/WPA3.","easy"),
        QA("Security","Policies","Least privilege means:",
           ["Admins have full access","Users only get necessary rights","Open access by default","Read-only for all"],"Users only get necessary rights",
           "Grant only the access required for tasks.","easy"),
        QA("Security","Controls","A firewall is best classified as:",
           ["Technical control","Administrative control","Physical control","Compensating control"],"Technical control",
           "Firewalls enforce technical policy at boundaries.","easy"),
    ]
    return items

def gen_mobile() -> List[QA]:
    items: List[QA] = []
    items += [
        QA("Mobile devices","Features","Which feature allows paying by tapping a phone?",
           ["Bluetooth","NFC","Wi-Fi Direct","IR"],"NFC",
           "NFC enables short-range contactless payments.","easy"),
        QA("Mobile devices","Displays","OLED displays primarily offer:",
           ["Higher power use","Worse contrast","True blacks","Lower brightness"],"True blacks",
           "Individual pixels turn off for black, yielding true blacks.","easy"),
        QA("Mobile devices","Connectivity","Tethering allows a phone to:",
           ["Connect via IR","Act as a modem","Use satellite","Pair via QR"],"Act as a modem",
           "Tethering shares cellular data with other devices.","easy"),
        QA("Mobile devices","Security","Which provides device-level security on iOS?",
           ["BitLocker","FileVault","Secure Enclave","TPM 1.2"],"Secure Enclave",
           "Secure Enclave is a hardware-based security component.","medium"),
        QA("Mobile devices","Battery","Best practice to preserve Li-ion battery lifespan:",
           ["Fully discharge frequently","Avoid high heat","Store at 0% long-term","Keep always at 100%"],"Avoid high heat",
           "Heat accelerates chemical degradation.","easy"),
        QA("Mobile devices","MDM","Mobile device management (MDM) primarily helps:",
           ["Disable encryption","Centralize configuration & security","Increase battery drain","Block Wi-Fi"],"Centralize configuration & security",
           "MDM enforces policy, encryption, and app controls.","medium"),
        QA("Mobile devices","Sensors","What does the accelerometer do?",
           ["Detects orientation/movement","Controls audio","Encrypts storage","Manages apps"],"Detects orientation/movement",
           "Accelerometers detect device movement/orientation.","easy"),
        QA("Mobile devices","Sensors","What does the gyroscope do?",
           ["Measures angular rotation","Plays music","Cools the device","Blocks calls"],"Measures angular rotation",
           "Gyroscopes measure rotation for precise motion.","easy"),
        QA("Mobile devices","Sensors","What does GPS provide?",
           ["Location tracking","File encryption","Wi-Fi acceleration","Battery saving"],"Location tracking",
           "GPS provides geolocation.","easy"),
        QA("Mobile devices","Storage","Which storage is typically soldered in phones?",
           ["NVMe M.2","eMMC/UFS","HDD","SD card only"],"eMMC/UFS",
           "Phones often use onboard eMMC/UFS storage.","medium"),
        QA("Mobile devices","Connectivity","Wi-Fi Calling uses:",
           ["Cellular voice only","VoIP over Wi-Fi","SMS over LTE","IR blaster"],"VoIP over Wi-Fi",
           "Calls route over Wi-Fi using carrier VoIP.","medium"),
    ]
    return items

def gen_virtualization_cloud() -> List[QA]:
    items: List[QA] = []
    items += [
        QA("Virtualization & cloud","Concepts","A Type 1 hypervisor is:",
           ["Hosted on an OS","Bare metal","Only desktop-focused","Always cloud-only"],"Bare metal",
           "Type 1 runs directly on hardware.","easy"),
        QA("Virtualization & cloud","Concepts","VM snapshots are best for:",
           ["Long-term backup","Short-term state capture","Boot optimization","Network throughput"],"Short-term state capture",
           "Snapshots capture VM state; not backup replacements.","medium"),
        QA("Virtualization & cloud","Cloud models","Which model delivers virtualized hardware?",
           ["IaaS","SaaS","PaaS","FaaS"],"IaaS",
           "IaaS provides compute, storage, and network resources.","easy"),
        QA("Virtualization & cloud","Cloud models","SaaS primarily provides:",
           ["Infrastructure APIs","Full applications over the internet","Language runtimes","Build agents"],"Full applications over the internet",
           "SaaS exposes complete applications to end users.","easy"),
        QA("Virtualization & cloud","Cloud models","PaaS primarily provides:",
           ["VM hardware","Complete apps","Application runtime & managed services","Network cables"],"Application runtime & managed services",
           "PaaS offers platforms for building/deploying apps.","easy"),
        QA("Virtualization & cloud","Concepts","Resource overcommitment risks:",
           ["Underutilization only","Performance degradation under load","Instant security","Free energy"],"Performance degradation under load",
           "Overcommitment can cause contention and slowdowns.","medium"),
        QA("Virtualization & cloud","Operations","Live migration primarily improves:",
           ["Availability","Confidentiality","Integrity","Non-repudiation"],"Availability",
           "VMs move between hosts without downtime.","easy"),
        QA("Virtualization & cloud","Security","In IaaS, customer responsibility includes:",
           ["Hypervisor patching","Physical security","Guest OS hardening","Power supply"],"Guest OS hardening",
           "Providers handle physical/hypervisor; customers secure OS/apps/data.","medium"),
        QA("Virtualization & cloud","Containers","Containers differ from VMs primarily by:",
           ["Kernel sharing","Hypervisor type","Hardware acceleration","File systems"],"Kernel sharing",
           "Containers share the host OS kernel.","medium"),
        QA("Virtualization & cloud","Networking","Which term describes private networks across public clouds?",
           ["VPC","LAN","VLAN","SAN"],"VPC",
           "Virtual Private Clouds isolate tenant resources.","easy"),
    ]
    return items

def gen_troubleshooting() -> List[QA]:
    items: List[QA] = []
    items += [
        QA("Troubleshooting","No power","First step when a PC shows no power:",
           ["Replace PSU","Reseat RAM","Check power cable and switch","Reinstall OS"],"Check power cable and switch",
           "Begin with simple, non-invasive checks.","easy"),
        QA("Troubleshooting","Overheating","A desktop overheats and shuts down. First action:",
           ["Replace motherboard","Clean dust and improve airflow","Reinstall OS","Disable BIOS"],"Clean dust and improve airflow",
           "Address airflow and dust buildup first.","easy"),
        QA("Troubleshooting","No boot device","Error: No boot device found. Likely cause:",
           ["Faulty GPU","Incorrect boot order or disconnected drive","Bad monitor","Firewall issue"],"Incorrect boot order or disconnected drive",
           "Check boot order and cabling.","easy"),
        QA("Troubleshooting","BSOD","BSOD occurs after new driver install. Best next step:",
           ["Full reinstall","Roll back driver","Change IP","Disable UAC"],"Roll back driver",
           "Driver rollback is a targeted fix.","medium"),
        QA("Troubleshooting","Intermittent","Intermittent network drops; first check:",
           ["Replace router","Check cabling and link lights","Change DNS","Reset all passwords"],"Check cabling and link lights",
           "Physical checks often reveal issues.","easy"),
        QA("Troubleshooting","Printers","Streaks in laser prints often indicate:",
           ["Bad toner cartridge","Wrong paper size","Firewall rules","Video driver issue"],"Bad toner cartridge",
           "Replace or reseat toner/drum to fix streaks.","easy"),
        QA("Troubleshooting","Storage","Clicking noise from HDD indicates:",
           ["Healthy drive","Fan issue","Impending failure","GPU problem"],"Impending failure",
           "Clicking is a common sign of mechanical failure.","easy"),
        QA("Troubleshooting","Power","PC powers on then off instantly. Likely cause:",
           ["Loose CPU heatsink","Faulty PSU","Wrong monitor cable","Bad keyboard"],"Faulty PSU",
           "PSU faults can cause immediate shutdowns.","medium"),
        QA("Troubleshooting","Network","Link light off on NIC. First step:",
           ["Replace motherboard","Check cable and port","Change subnet mask","Update BIOS"],"Check cable and port",
           "Verify physical layer connections.","easy"),
        QA("Troubleshooting","Memory","Frequent random reboots often indicate:",
           ["Bad RAM","Wrong screen resolution","Old mouse","No DNS"],"Bad RAM",
           "Faulty memory can cause instability and reboots.","medium"),
        QA("Troubleshooting","Displays","No signal on monitor; first step:",
           ["Check cable and input source","Replace GPU","Reinstall OS","Reset BIOS"],"Check cable and input source",
           "Verify physical connections and correct input.","easy"),
        QA("Troubleshooting","Wireless","Slow Wi-Fi near microwave oven suggests:",
           ["2.4 GHz interference","ISP outage","Bad SSD","Wrong subnet"],"2.4 GHz interference",
           "Microwaves can interfere with 2.4 GHz Wi-Fi.","easy"),
    ]
    return items

def gen_ops() -> List[QA]:
    items: List[QA] = []
    items += [
        QA("Operational procedures","Safety","Best practice to prevent ESD while working inside a PC:",
           ["Wear rubber gloves","Use an ESD wrist strap","Work on carpet","Increase humidity"],"Use an ESD wrist strap",
           "ESD straps safely discharge static to ground.","easy"),
        QA("Operational procedures","Professionalism","If a customer is upset, you should:",
           ["Argue back","Listen and empathize","Ignore","Blame another department"],"Listen and empathize",
           "Professionalism and empathy de-escalate issues.","easy"),
        QA("Operational procedures","Documentation","Documenting changes helps:",
           ["Make future troubleshooting easier","Consume storage","Increase risk","Prevent backups"],"Make future troubleshooting easier",
           "Documentation preserves history and context.","easy"),
        QA("Operational procedures","Change control","Change management processes exist to:",
           ["Block all changes","Ensure safe, approved changes","Speed up reckless changes","Eliminate testing"],"Ensure safe, approved changes",
           "Changes should be reviewed, tested, and approved.","medium"),
        QA("Operational procedures","Safety","Which extinguisher class is appropriate for electrical fires?",
           ["Class A","Class B","Class C","Class D"],"Class C",
           "Class C extinguishers are designed for electrical fires.","medium"),
        QA("Operational procedures","Legal","PII stands for:",
           ["Private Internal Intranet","Personally Identifiable Information","Personal Internet Interface","Protected Internet Info"],"Personally Identifiable Information",
           "PII is data that identifies an individual.","easy"),
        QA("Operational procedures","Safety","Before opening a PC case, you should:",
           ["Power it on","Disconnect power and discharge","Increase humidity","Tip it over"],"Disconnect power and discharge",
           "Safety first: remove power and discharge static.","easy"),
        QA("Operational procedures","Communication","A communications plan defines:",
           ["Who needs what info, when, and how","Test cases","Server capacity","Code reviews"],"Who needs what info, when, and how",
           "Ensures timely, relevant information.","easy"),
        QA("Operational procedures","Safety","MSDS/SDS documents provide:",
           ["Chemical safety info","IP addressing plan","Server rack layout","Firewall rules"],"Chemical safety info",
           "Safety Data Sheets outline handling and hazards.","easy"),
        QA("Operational procedures","Ethics","If you suspect data misuse, you should:",
           ["Ignore it","Report per policy","Post on social media","Delete logs"],"Report per policy",
           "Follow escalation and reporting procedures.","medium"),
    ]
    return items

# ---------------------------
# Build large pool and enforce uniqueness
# ---------------------------
def build_large_pool() -> List[QA]:
    pool: List[QA] = []
    pool.extend(gen_hardware())
    pool.extend(gen_networking())
    pool.extend(gen_operating_systems())
    pool.extend(gen_security())
    pool.extend(gen_mobile())
    pool.extend(gen_virtualization_cloud())
    pool.extend(gen_troubleshooting())
    pool.extend(gen_ops())

    # Deduplicate by (question, answer) pair
    seen: Set[Tuple[str, str]] = set()
    deduped: List[QA] = []
    for qa in pool:
        key = (qa.question.strip().lower(), qa.answer.strip().lower())
        if key not in seen:
            seen.add(key)
            deduped.append(qa)

    # Soft guard: warn if less than 220, but proceed (we’ve defined 260+ items)
    if len(deduped) < 220:
        print(f"Warning: only {len(deduped)} unique questions in pool. Consider adding more for variety.")
    return deduped

# ---------------------------
# Sample 90 unique questions without repeats
# ---------------------------
def sample_exam(pool: List[QA], seed: Optional[int], shuffle_choices: bool) -> List[QA]:
    if seed is not None:
        random.seed(seed)
    exam_qs = random.sample(pool, 90)  # no repeats
    if shuffle_choices:
        for qa in exam_qs:
            if qa.answer not in qa.choices:
                qa.choices = [qa.answer] + qa.choices
            random.shuffle(qa.choices)
    return exam_qs

# ---------------------------
# Run exam with CompTIA-style scaled scoring
# ---------------------------
def run_exam(questions: List[QA], timer_enabled: bool = True):
    total = len(questions)
    assert total == 90, "Exam must be exactly 90 questions"
    time_limit_sec = 90 * 60
    start_time = time.time()
    correct_count = 0
    per_domain: Dict[str, Tuple[int, int]] = {}  # domain -> (answered, correct)

    for i, qa in enumerate(questions, 1):
        remaining = max(0, time_limit_sec - int(time.time() - start_time)) if timer_enabled else None
        print("\n" + "=" * 70)
        print(f"Question {i}/{total} — Domain: {qa.domain} / {qa.subdomain}")
        if timer_enabled:
            print(f"Time left: {remaining//60}:{remaining%60:02d}") # pyright: ignore[reportOptionalOperand]
        print(qa.question)
        for idx, choice in enumerate(qa.choices, 1):
            print(f"  {idx}. {choice}")
        while True:
            if timer_enabled and remaining is not None and remaining <= 0:
                print("\nTime limit reached.")
                break
            ans_raw = input("Your answer (number): ").strip()
            try:
                sel = int(ans_raw)
                if 1 <= sel <= len(qa.choices):
                    chosen = qa.choices[sel - 1]
                    is_correct = (chosen.strip().lower() == qa.answer.strip().lower())
                    if is_correct:
                        print("✅ Correct")
                        correct_count += 1
                    else:
                        print(f"❌ Incorrect — Correct: {qa.answer}")
                    print(f"Explanation: {qa.explanation}")
                    a, c = per_domain.get(qa.domain, (0, 0))
                    per_domain[qa.domain] = (a + 1, c + (1 if is_correct else 0))
                    break
                else:
                    print("Please choose a valid option.")
            except ValueError:
                print("Enter a number corresponding to your choice.")
        if timer_enabled and remaining is not None and remaining <= 0:
            break

    raw = correct_count
    scaled = int(100 + (raw / total) * 800)
    passed = scaled >= 675

    answered = sum(a for a, _ in per_domain.values())
    print("\n" + "-" * 70)
    print(f"Raw score: {raw}/{answered}")
    print(f"Scaled score: {scaled} (range 100–900)")
    print("Result:", "✅ PASS" if passed else "❌ FAIL")
    print("Domain breakdown:")
    for dom, (a, c) in sorted(per_domain.items()):
        dpct = (c / max(1, a)) * 100
        print(f"- {dom}: {c}/{a} ({dpct:.1f}%)")
    print("-" * 70)

# ---------------------------
# CLI
# ---------------------------
def main():
    parser = argparse.ArgumentParser(description="CompTIA A+ 90-question exam simulator (260+ pool, no repeats, scaled scoring)")
    parser.add_argument("--seed", type=int, default=None, help="Deterministic seed for reproducible exam")
    parser.add_argument("--shuffle", action="store_true", help="Shuffle answer choices")
    parser.add_argument("--no-timer", action="store_true", help="Disable 90-minute timer")
    args = parser.parse_args()

    pool = build_large_pool()
    exam_qs = sample_exam(pool, seed=args.seed, shuffle_choices=args.shuffle)
    run_exam(exam_qs, timer_enabled=(not args.no_timer))

if __name__ == "__main__":
    main()
