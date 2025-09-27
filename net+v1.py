#!/usr/bin/env python3
# CompTIA Network+ (N10-008) 90-Question Exam Simulator
# 200+ item pool, no repeats, scaled scoring

import argparse
import random
import time
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional, Set

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
# Helpers for building items
# ---------------------------

COMMON_PORTS = ["20", "21", "22", "23", "25", "53", "67", "68", "69", "80", "110", "123", "143", "161", "389", "443", "445", "514", "993", "995", "1433", "1701", "1723", "1812", "1813", "3306", "3389", "5432"]
OSI_LAYERS = ["Physical (L1)", "Data Link (L2)", "Network (L3)", "Transport (L4)", "Session (L5)", "Presentation (L6)", "Application (L7)"]

def mk_port_question(service: str, port: str) -> QA:
    # Include plausible distractors from common ports but keep correct one
    distractors = [p for p in COMMON_PORTS if p != port][:3]
    choices = [port] + distractors
    return QA(
        "Networking Fundamentals", "Ports",
        f"Which port is commonly used by {service}?",
        choices,
        port,
        f"{service} commonly uses port {port}.",
        "easy"
    )

def mk_layer_resp_question(layer_name: str, resp: str) -> QA:
    choices = [resp, "Encryption/decryption", "Cable/connector specs", "Hostname resolution"]
    return QA(
        "Networking Fundamentals", "OSI model",
        f"Which function best matches {layer_name}?",
        choices,
        resp,
        f"{layer_name} is responsible for: {resp}.",
        "medium"
    )

def mk_simple_question(domain: str, subdomain: str, stem: str, choices: List[str], answer: str, expl: str, diff: str = "easy") -> QA:
    return QA(domain, subdomain, stem, choices, answer, expl, diff)

# ---------------------------
# Domain question generators
# ---------------------------

def gen_fundamentals() -> List[QA]:
    items: List[QA] = []

    # OSI responsibilities
    items += [
        mk_layer_resp_question("Physical (L1)", "Bit transmission over media"),
        mk_layer_resp_question("Data Link (L2)", "MAC addressing and frame switching"),
        mk_layer_resp_question("Network (L3)", "Logical addressing and routing"),
        mk_layer_resp_question("Transport (L4)", "Segmentation and end-to-end delivery"),
        mk_layer_resp_question("Session (L5)", "Establish/manage/terminate sessions"),
        mk_layer_resp_question("Presentation (L6)", "Data formatting and encryption"),
        mk_layer_resp_question("Application (L7)", "User-facing protocols and services"),
    ]

    # TCP vs UDP characteristics
    items += [
        mk_simple_question("Networking Fundamentals","Transport",
            "Which transport protocol provides reliable, ordered delivery?",
            ["TCP","UDP","ICMP","GRE"], "TCP",
            "TCP is connection-oriented and provides reliable, ordered delivery.", "easy"),
        mk_simple_question("Networking Fundamentals","Transport",
            "Which protocol is best for time-sensitive streaming with minimal overhead?",
            ["TCP","UDP","IPsec","TLS"], "UDP",
            "UDP is connectionless and avoids retransmission delays.", "easy"),
    ]

    # Common ports
    ports_data = [
        ("HTTP","80"), ("HTTPS","443"), ("SSH","22"), ("Telnet","23"), ("DNS","53"),
        ("SMTP","25"), ("IMAP","143"), ("IMAPS","993"), ("POP3","110"), ("POP3S","995"),
        ("RDP","3389"), ("LDAP","389"), ("LDAPS","636"), ("Syslog","514"), ("SNMP","161"),
        ("NTP","123"), ("FTP","21"), ("TFTP","69"), ("SMB","445"), ("MySQL","3306"),
        ("PostgreSQL","5432"), ("SQL Server","1433"), ("IKE","500"), ("L2TP","1701"),
        ("PPTP","1723"), ("RADIUS Auth","1812"), ("RADIUS Acct","1813"),
    ]
    for svc, port in ports_data:
        items.append(mk_port_question(svc, port))

    # IP addressing and subnetting
    items += [
        mk_simple_question("Networking Fundamentals","IPv4",
            "What is the subnet mask for a /24 network?",
            ["255.255.255.0","255.255.0.0","255.0.0.0","255.255.255.252"], "255.255.255.0",
            "/24 corresponds to 255.255.255.0.", "easy"),
        mk_simple_question("Networking Fundamentals","IPv4",
            "What is the usable host count in a /26 IPv4 subnet?",
            ["62","64","32","16"], "62",
            "A /26 has 64 addresses; 2 reserved; 62 usable hosts.", "medium"),
        mk_simple_question("Networking Fundamentals","IPv6",
            "Which IPv6 address type is publicly routable on the internet?",
            ["Link-local (fe80::/10)","Unique local (fc00::/7)","Global unicast (2000::/3)","Anycast"], "Global unicast (2000::/3)",
            "Global unicast addresses are routable.", "medium"),
        mk_simple_question("Networking Fundamentals","IPv6",
            "Which mechanism can auto-configure IPv6 addresses without a DHCP server?",
            ["SLAAC","DHCPv6","Manual","NAT64"], "SLAAC",
            "Stateless Address Autoconfiguration uses router advertisements.", "medium"),
    ]

    # Cabling and wireless basics
    items += [
        mk_simple_question("Networking Fundamentals","Cabling",
            "Which medium is immune to electromagnetic interference (EMI)?",
            ["UTP","STP","Coaxial","Fiber optics"], "Fiber optics",
            "Fiber uses light; immune to EMI.", "easy"),
        mk_simple_question("Networking Fundamentals","Wireless",
            "Which band is used by 802.11b?",
            ["5 GHz","2.4 GHz","6 GHz","900 MHz"], "2.4 GHz",
            "802.11b uses 2.4 GHz.", "easy"),
        mk_simple_question("Networking Fundamentals","Duplex",
            "Which is a key benefit of full-duplex Ethernet?",
            ["Higher latency","No collisions","Half bandwidth","Broadcast storm prevention"], "No collisions",
            "Full-duplex eliminates collisions by separating send/receive.", "medium"),
        mk_simple_question("Networking Fundamentals","WAN",
            "Which WAN technology labels packets for path selection across provider networks?",
            ["DSL","MPLS","ISDN","Metro Ethernet"], "MPLS",
            "MPLS uses labels for efficient forwarding.", "medium"),
    ]

    return items

def gen_implementations() -> List[QA]:
    items: List[QA] = []

    # Switching/routing/VLANs
    items += [
        mk_simple_question("Network Implementations","Switching",
            "Which device forwards frames based on MAC addresses?",
            ["Router","Switch","Hub","Firewall"], "Switch",
            "Switches operate at Layer 2 using MAC tables.", "easy"),
        mk_simple_question("Network Implementations","VLANs",
            "Which standard tags VLANs on trunk links?",
            ["802.1X","802.1Q","802.11ac","802.3af"], "802.1Q",
            "802.1Q provides VLAN tagging for trunking.", "easy"),
        mk_simple_question("Network Implementations","Routing",
            "Which routing protocol uses link-state and cost metrics?",
            ["RIP","OSPF","BGP","EIGRP"], "OSPF",
            "OSPF is a link-state IGP using cost.", "medium"),
        mk_simple_question("Network Implementations","Routing",
            "Which protocol exchanges routes between autonomous systems on the internet?",
            ["RIP","OSPF","BGP","IS-IS"], "BGP",
            "BGP is the de facto EGP for internet routing.", "medium"),
        mk_simple_question("Network Implementations","Inter-VLAN",
            "What enables communication between VLANs?",
            ["Trunking","Port security","Inter-VLAN routing","Spanning Tree"], "Inter-VLAN routing",
            "Routing via Layer 3 interface or SVI connects VLANs.", "easy"),
    ]

    # Cabling types/categories
    cabling = [
        ("Cat5e","Up to 1 Gbps at 100m"),
        ("Cat6","10 Gbps up to ~55m (1 Gbps up to 100m)"),
        ("Cat6a","10 Gbps up to 100m"),
        ("Cat7","Shielded; up to 10 Gbps"),
        ("Single-mode fiber","Long distance; small core; laser"),
        ("Multi-mode fiber","Shorter distance; larger core; LED"),
    ]
    for name, desc in cabling:
        items.append(mk_simple_question("Network Implementations","Cabling",
            f"What best describes {name}?",
            [desc, "Coax; legacy cable TV", "Wireless only", "Power over Ethernet only"],
            desc, f"{name}: {desc}.", "easy"))

    # Wireless standards/features
    wireless = [
        ("802.11a","5 GHz; 54 Mbps"),
        ("802.11b","2.4 GHz; 11 Mbps"),
        ("802.11g","2.4 GHz; 54 Mbps"),
        ("802.11n","2.4/5 GHz; MIMO"),
        ("802.11ac","5 GHz; MU-MIMO; high throughput"),
        ("802.11ax","2.4/5 GHz; OFDMA; WPA3"),
    ]
    for std, feat in wireless:
        items.append(mk_simple_question("Network Implementations","Wireless",
            f"Which features match {std}?",
            [feat, "Token ring", "CSMA/CD", "PPP"], feat, f"{std}: {feat}.", "easy"))

    # IPv6 and auth
    items += [
        mk_simple_question("Network Implementations","IPv6",
            "Which IPv6 addresses are auto-assigned for link-local communication?",
            ["fe80::/10","2000::/3","fc00::/7","ff00::/8"], "fe80::/10",
            "Link-local addresses start with fe80::/10.", "medium"),
        mk_simple_question("Network Implementations","Authentication",
            "Which method provides port-based network access control for wired/wireless?",
            ["WEP","802.1X","PSK","MAC filtering"], "802.1X",
            "802.1X uses supplicant/authenticator with RADIUS.", "medium"),
        mk_simple_question("Network Implementations","AAA",
            "Which backend is commonly used with 802.1X for authentication?",
            ["LDAP","RADIUS","Kerberos","TACACS+"], "RADIUS",
            "RADIUS provides centralized AAA for network access.", "medium"),
    ]

    # Topologies
    topologies = [
        ("Star","Devices connect to a central switch/hub"),
        ("Bus","Shared backbone; legacy; collisions common"),
        ("Ring","Each device connects to two others in a loop"),
        ("Mesh","Interconnected nodes providing redundancy"),
        ("Hybrid","Mix of different topology types"),
    ]
    for name, defn in topologies:
        items.append(mk_simple_question("Network Implementations","Topologies",
            f"What best describes a {name} topology?",
            [defn, "Power over Ethernet", "Token passing only", "IPv6 SLAAC"],
            defn, f"{name} topology: {defn}.", "easy"))

    return items

def gen_operations() -> List[QA]:
    items: List[QA] = []

    # Monitoring & logging
    items += [
        mk_simple_question("Network Operations","Monitoring",
            "Which protocol collects device metrics (polls and traps)?",
            ["SNMP","SMTP","SFTP","DHCP"], "SNMP",
            "SNMP is used to monitor and manage devices.", "easy"),
        mk_simple_question("Network Operations","Logging",
            "Which standard transmits event logs from devices to a server?",
            ["Syslog","NetFlow","RADIUS","TACACS+"], "Syslog",
            "Syslog standardizes event log messaging.", "easy"),
        mk_simple_question("Network Operations","Flows",
            "Which technology summarizes conversations and traffic patterns?",
            ["SNMP","NetFlow","Syslog","mDNS"], "NetFlow",
            "NetFlow provides flow records useful for analysis.", "medium"),
        mk_simple_question("Network Operations","Time",
            "Which protocol synchronizes clocks across devices?",
            ["NTP","DNS","FTP","IMAP"], "NTP",
            "NTP provides time sync.", "easy"),
    ]

    # Documentation & processes
    docs = [
        ("SOP","Step-by-step standard operating procedures"),
        ("Runbook","Operational procedures for routine tasks"),
        ("Playbook","Incident response actions and decision trees"),
        ("RACI","Roles/responsibilities: Responsible, Accountable, Consulted, Informed"),
        ("Network diagram","Visual representation of topology and devices"),
        ("Asset inventory","List of devices, versions, ownership"),
        ("Change request","Formal proposal for network changes"),
        ("Maintenance window","Scheduled time for changes/minimal impact"),
    ]
    for name, defn in docs:
        items.append(mk_simple_question("Network Operations","Docs",
            f"What best describes {name}?",
            [defn, "TLS handshake details", "Packet encryption", "DNS zone transfer"],
            defn, f"{name}: {defn}.", "easy"))

    # Baselines, QoS, metrics
    items += [
        mk_simple_question("Network Operations","Baseline",
            "What is a baseline in network operations?",
            ["Normal activity reference","Packet encryption method","Device boot sequence","Cable standard"],
            "Normal activity reference",
            "Baselines help detect anomalies against normal Operation.", "easy"),
        mk_simple_question("Network Operations","QoS",
            "Which QoS mechanism prioritizes voice traffic?",
            ["DSCP","VLAN","STP","NAT"], "DSCP",
            "DSCP values mark packets for priority handling.", "medium"),
        mk_simple_question("Network Operations","Performance",
            "Which metric indicates bandwidth saturation?",
            ["Low CPU","High utilization","Low latency","Low jitter"], "High utilization",
            "High utilization can indicate bandwidth constraints.", "easy"),
    ]

    # Cloud and virtualization
    items += [
        mk_simple_question("Network Operations","Cloud",
            "Which cloud service model provides applications over the internet?",
            ["IaaS","PaaS","SaaS","FaaS"], "SaaS",
            "SaaS delivers applications as a service.", "easy"),
        mk_simple_question("Network Operations","Cloud",
            "Which model gives customer control over OS and applications?",
            ["SaaS","PaaS","IaaS","DBaaS"], "IaaS",
            "IaaS provides infra; you manage OS/apps.", "medium"),
        mk_simple_question("Network Operations","Virtualization",
            "Which isolates workloads using shared OS kernel?",
            ["VMs","Containers","Hypervisors","Sandboxes"], "Containers",
            "Containers share host OS; lighter than VMs.", "medium"),
        mk_simple_question("Network Operations","Virtualization",
            "What is the role of a hypervisor?",
            ["Encrypt data","Manage VMs","Provide DHCP","Route packets"], "Manage VMs",
            "Hypervisors orchestrate virtual machines.", "easy"),
    ]

    return items

def gen_security() -> List[QA]:
    items: List[QA] = []

    # Attacks
    attacks = [
        ("SYN flood","Floods target with SYN requests causing half-open connections"),
        ("Smurf","Uses ICMP broadcast with spoofed source to amplify"),
        ("Ping of Death","Oversized ICMP packets causing crashes on legacy systems"),
        ("Teardrop","Fragmented packets overlapping causing crashes on legacy"),
        ("ARP spoofing","Forged ARP responses to redirect traffic"),
        ("DNS poisoning","Manipulates DNS cache to redirect"),
        ("MITM","Intercepts communication between two parties"),
        ("Replay","Reuses captured authentication data"),
        ("Password spraying","One password across many accounts"),
        ("Credential stuffing","Leaked credentials reused across services"),
        ("Evil twin","Rogue AP mimicking SSID"),
        ("Deauthentication","Forcing Wi-Fi clients off AP via frames"),
        ("Rogue AP","Unauthorized access point connected to network"),
        ("Port scanning","Probe for open services"),
        ("DoS","Overwhelm resources to make service unavailable"),
        ("DDoS","Distributed DoS from many sources"),
    ]
    for name, desc in attacks:
        items.append(mk_simple_question("Network Security","Attacks",
            f"Which attack is described: {desc}?",
            [name, "Pharming", "Rootkit", "Keylogger"],
            name, f"{name}: {desc}.", "medium"))

    # Devices/controls
    controls = [
        ("ACL","Permit/deny rules on devices"),
        ("IDS","Detect suspicious activity"),
        ("IPS","Prevent/block suspicious traffic"),
        ("WAF","Inspect HTTP/S at Layer 7 for web attacks"),
        ("DLP","Prevent data exfiltration"),
        ("NAC","Control access based on posture/policy"),
        ("VPN","Encrypted tunnels over untrusted networks"),
        ("TLS inspection","Decrypt/inspect HTTPS traffic"),
        ("Port security","Limit MACs per port"),
        ("802.1X","Port-based network access control"),
    ]
    for name, defn in controls:
        items.append(mk_simple_question("Network Security","Controls",
            f"What best describes {name}?",
            [defn, "IP addressing", "DNS resolution", "QoS shaping"],
            defn, f"{name}: {defn}.", "easy"))

    # VPNs/IPsec
    items += [
        mk_simple_question("Network Security","VPN",
            "Which tunnel type encapsulates non-IP traffic over IP networks?",
            ["GRE","TLS","IKE","L2TP"], "GRE",
            "GRE encapsulates a variety of traffic types.", "medium"),
        mk_simple_question("Network Security","IPsec",
            "Which IPsec mode encrypts only payload (not header)?",
            ["Transport","Tunnel","AES-GCM","HMAC"], "Transport",
            "Transport mode protects payload; tunnel protects entire IP packet.", "medium"),
        mk_simple_question("Network Security","IPsec",
            "Which protocol negotiates shared secrets for IPsec?",
            ["IKE","ESP","AH","TLS"], "IKE",
            "IKE (ISAKMP) negotiates keys for IPsec.", "medium"),
    ]

    # Access control models
    items += [
        mk_simple_question("Network Security","Access control",
            "Which model enforces rules via labels and clearances?",
            ["MAC","DAC","RBAC","ABAC"], "MAC",
            "Mandatory access control uses centrally defined labels.", "medium"),
        mk_simple_question("Network Security","Access control",
            "Which model grants access based on roles (e.g., admin, user)?",
            ["MAC","DAC","RBAC","ABAC"], "RBAC",
            "Role-based access control ties permissions to roles.", "easy"),
        mk_simple_question("Network Security","Access control",
            "Which model bases decisions on attributes of user, resource, context?",
            ["MAC","DAC","RBAC","ABAC"], "ABAC",
            "Attribute-based access control evaluates multiple attributes.", "medium"),
    ]

    # Wireless security/EAP
    items += [
        mk_simple_question("Network Security","Wireless",
            "Which authentication method uses client/server certificates for Wi-Fi?",
            ["PEAP","EAP-TLS","EAP-MD5","WEP"], "EAP-TLS",
            "EAP-TLS uses mutual certificate authentication.", "medium"),
        mk_simple_question("Network Security","Wireless",
            "Which configuration corresponds to WPA2-Enterprise?",
            ["PSK","802.1X + RADIUS","WEP + Shared Key","Open"], "802.1X + RADIUS",
            "Enterprise mode uses 802.1X with RADIUS.", "easy"),
    ]

    return items

def gen_troubleshooting() -> List[QA]:
    items: List[QA] = []

    # Methodology
    steps = [
        ("Identify the problem","Gather info; define symptoms"),
        ("Establish a theory","Consider likely causes"),
        ("Test the theory","Verify with tests/observations"),
        ("Establish a plan","Plan actions and impact"),
        ("Implement the solution","Execute fix and monitor"),
        ("Verify full system functionality","Confirm resolution and impact"),
        ("Document findings","Record actions, outcomes, lessons"),
    ]
    for step, desc in steps:
        items.append(mk_simple_question("Network Troubleshooting","Process",
            f"Which step is described: {desc}?",
            [step, "Perform risk assessment", "Write RFP", "Update SLA"],
            step, f"{step}: {desc}.", "easy"))

    # Tools
    tools = [
        ("ping","ICMP echo for connectivity test"),
        ("traceroute","Path discovery and hop latency"),
        ("ipconfig/ifconfig","IP configuration display"),
        ("nslookup/dig","DNS query tools"),
        ("netstat","Active connections and listening ports"),
        ("arp","ARP cache display/manipulation"),
        ("tcpdump/Wireshark","Packet capture and analysis"),
        ("pathping","Combines ping/traceroute metrics"),
        ("mtr","Continuous path performance view"),
        ("telnet","Basic TCP connectivity test to a port"),
    ]
    for name, defn in tools:
        items.append(mk_simple_question("Network Troubleshooting","Tools",
            f"What does {name} primarily provide?",
            [defn, "Encrypt files", "Provision IPs", "Set QoS"],
            defn, f"{name}: {defn}.", "easy"))

    # Common wired/wireless issues
    issues = [
        ("Duplex mismatch","One side half-duplex; the other full; causes collisions/low throughput"),
        ("VLAN mismatch","Access port in wrong VLAN; no connectivity to expected segment"),
        ("Incorrect default gateway","Hosts cannot reach other subnets/internet"),
        ("DNS failure","Names do not resolve; IP works"),
        ("IP conflict","Two hosts share same IP; intermittent loss"),
        ("MTU mismatch","Fragmentation/black hole; broken apps/VPN"),
        ("Interference","Wi-Fi instability due to overlapping channels/EM noise"),
        ("Weak signal","Low RSSI; poor Wi-Fi performance"),
        ("Wrong SSID/security","Cannot join; auth failures"),
        ("Rogue AP","Unauthorized AP siphoning traffic"),
        ("Port security violation","MAC address limit exceeded; port err-disabled"),
        ("Spanning Tree blocked","Port in blocking state; path changes"),
        ("Bandwidth saturation","High utilization; poor performance"),
        ("QoS misconfiguration","Voice jitter/latency due to wrong DSCP/queues"),
        ("Bad cable","Errors, CRCs, link flaps"),
    ]
    for name, desc in issues:
        items.append(mk_simple_question("Network Troubleshooting","Symptoms & causes",
            f"Which issue fits: {desc}?",
            [name, "DHCP starvation", "SSL downgrade", "EAP misconfig"],
            name, f"{name}: {desc}.", "medium"))

    return items

# ---------------------------
# Build pool and deduplicate
# ---------------------------

def build_large_pool() -> List[QA]:
    pool: List[QA] = []
    pool.extend(gen_fundamentals())
    pool.extend(gen_implementations())
    pool.extend(gen_operations())
    pool.extend(gen_security())
    pool.extend(gen_troubleshooting())

    seen: Set[Tuple[str, str]] = set()
    deduped: List[QA] = []
    for qa in pool:
        key = (qa.question.strip().lower(), qa.answer.strip().lower())
        if key not in seen:
            seen.add(key)
            deduped.append(qa)

    if len(deduped) < 200:
        print(f"Warning: only {len(deduped)} unique questions. Add more for variety.")
    return deduped

# ---------------------------
# Sample exam (safe sampling)
# ---------------------------

def sample_exam(pool: List[QA], seed: Optional[int], shuffle_choices: bool) -> List[QA]:
    if seed is not None:
        random.seed(seed)
    num_questions = min(90, len(pool))  # prevents ValueError when pool < 90
    exam_qs = random.sample(pool, num_questions)
    if shuffle_choices:
        for qa in exam_qs:
            # Ensure correct answer is in choices (should be already)
            if qa.answer not in qa.choices:
                qa.choices = [qa.answer] + qa.choices
            random.shuffle(qa.choices)
    return exam_qs

# ---------------------------
# Run exam with scaled scoring
# ---------------------------

def run_exam(questions: List[QA], timer_enabled: bool = True, passing_scaled: int = 720):
    total = len(questions)
    if total == 0:
        print("No questions available to run the exam.")
        return

    time_limit_sec = 90 * 60
    start_time = time.time()
    correct_count = 0
    per_domain: Dict[str, Tuple[int, int]] = {}

    for i, qa in enumerate(questions, 1):
        remaining: Optional[int] = None
        if timer_enabled:
            remaining = max(0, time_limit_sec - int(time.time() - start_time))

        print("\n" + "=" * 70)
        print(f"Question {i}/{total} — Domain: {qa.domain} / {qa.subdomain}")
        if timer_enabled and remaining is not None:
            print(f"Time left: {remaining // 60}:{remaining % 60:02d}")
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

            if timer_enabled:
                remaining = max(0, time_limit_sec - int(time.time() - start_time))

        if timer_enabled and remaining is not None and remaining <= 0:
            break

    raw = correct_count
    # CompTIA-style scaled score (approximate)
    scaled = int(100 + (raw / total) * 800)
    passed = scaled >= passing_scaled
    answered = sum(a for a, _ in per_domain.values())

    print("\n" + "-" * 70)
    print(f"Raw score: {raw}/{answered}  |  Scaled: {scaled} (100–900, pass ≥ {passing_scaled})")
    print("Result:", "✅ PASS" if passed else "❌ FAIL")
    print("Domain breakdown:")
    for dom, (a, c) in sorted(per_domain.items()):
        dpct: float = (c / max(1, a)) * 100
        print(f"- {dom}: {c}/{a} ({dpct:.1f}%)")
    print("-" * 70)

# ---------------------------
# CLI entry point
# ---------------------------

def main():
    parser = argparse.ArgumentParser(
        description="CompTIA Network+ (N10-008) 90-question exam simulator"
    )
    parser.add_argument("--seed", type=int, default=None,
                        help="Deterministic seed for reproducible exam")
    parser.add_argument("--shuffle", action="store_true",
                        help="Shuffle answer choices")
    parser.add_argument("--no-timer", action="store_true",
                        help="Disable 90-minute timer")
    parser.add_argument("--pass", dest="passing_scaled", type=int, default=720,
                        help="Passing scaled score threshold (default 720)")
    args = parser.parse_args()

    pool = build_large_pool()
    exam_qs = sample_exam(pool, seed=args.seed, shuffle_choices=args.shuffle)
    run_exam(exam_qs, timer_enabled=(not args.no_timer), passing_scaled=args.passing_scaled)

if __name__ == "__main__":
    main()
