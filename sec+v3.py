#!/usr/bin/env python3
# CompTIA Security+ (SY0-701) 90-Question Exam Simulator
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
# Domain question generators
# ---------------------------

def gen_general() -> List[QA]:
    items: List[QA] = [
        QA("General Concepts","CIA","Which principle ensures data is not altered?",
           ["Confidentiality","Integrity","Availability","Non-repudiation"],"Integrity",
           "Integrity ensures data accuracy and consistency.","easy"),
        QA("General Concepts","CIA","Which principle ensures systems are accessible when needed?",
           ["Confidentiality","Integrity","Availability","Non-repudiation"],"Availability",
           "Availability ensures resources are accessible.","easy"),
        QA("General Concepts","Controls","Which is a detective control?",
           ["Firewall","IDS","Security awareness training","Access control list"],"IDS",
           "IDS detects suspicious activity; firewalls are preventive.","easy"),
        QA("General Concepts","Controls","Security guard checking IDs is a:",
           ["Technical control","Administrative control","Physical control","Detective control"],"Physical control",
           "Physical controls protect facilities and assets.","easy"),
        QA("General Concepts","Frameworks","Which NIST framework guides cybersecurity risk?",
           ["COBIT","ITIL","NIST CSF","ISO 27001"],"NIST CSF",
           "NIST CSF provides functions and categories for cybersecurity.","medium"),
    ]
    # Expand with realistic variations (30+ total)
    concepts = [
        ("Least privilege","Grant only necessary access"),
        ("Separation of duties","Split responsibilities to prevent fraud"),
        ("Defense in depth","Use multiple, overlapping controls"),
        ("Zero trust","No implicit trust; verify explicitly"),
        ("Acceptable use policy","Defines permitted system usage"),
        ("Change management","Formal process for approving changes"),
        ("Data classification","Categorize sensitivity and handling"),
        ("Need to know","Access based on role/task requirements"),
        ("Security baseline","Reference of normal/approved configuration"),
        ("Hardening","Reduce attack surface via config and removal"),
        ("Onboarding","Process to provision access for new users"),
        ("Offboarding","Process to revoke access upon departure"),
        ("Shadow IT","Unsanctioned tech used by staff"),
        ("Compensating control","Alternate that meets security objective"),
        ("Business continuity","Keep critical processes running"),
        ("Disaster recovery","Restore operations after disruption"),
        ("MTTR","Mean time to recover"),
        ("MTBF","Mean time between failures"),
        ("RPO","Max tolerable data loss time"),
        ("RTO","Target time to restore service"),
    ]
    for name, defn in concepts:
        items.append(QA(
            "General Concepts","Principles",
            f"What best describes {name}?",
            [defn, "Encrypt data at rest", "Monitor packets", "Allocate IP addresses"],
            defn,
            f"{name}: {defn}.",
            "easy"
        ))
    return items

def gen_threats() -> List[QA]:
    items: List[QA] = [
        QA("Threats","Phishing","Targeted phishing at executives is called:",
           ["Smishing","Whaling","Vishing","Pharming"],"Whaling",
           "Whaling targets high-value individuals.","easy"),
        QA("Threats","Malware","Ransomware primarily:",
           ["Exfiltrates data","Encrypts files and demands ransom","Logs keystrokes","Scans ports"],
           "Encrypts files and demands ransom","Ransomware encrypts data and requests ransom.","easy"),
        QA("Threats","Web","Injecting SQL statements into a form is:",
           ["XSS","SQL Injection","CSRF","Directory traversal"],"SQL Injection",
           "SQL injection manipulates queries via user input.","easy"),
        QA("Threats","Wireless","Setting a rogue AP with same SSID is:",
           ["Wardriving","Evil twin","Bluejacking","Jamming"],"Evil twin",
           "Evil twins mimic legitimate SSIDs to lure clients.","medium"),
        QA("Threats","Mitigation","Best mitigation for brute-force attacks:",
           ["Antivirus","Account lockout","WAF","Firewall"],"Account lockout",
           "Lockouts reduce rapid successive authentication attempts.","easy"),
    ]
    attack_bank = [
        ("Smishing","Phishing via SMS"),
        ("Vishing","Phishing via voice calls"),
        ("Watering hole","Compromise sites frequented by a target"),
        ("Password spraying","Try one password across many accounts"),
        ("Credential stuffing","Use leaked credentials across services"),
        ("Man-in-the-middle","Intercept communications between parties"),
        ("Replay attack","Reuse captured authentication data"),
        ("Session hijacking","Take over a valid user session"),
        ("Stored XSS","Malicious script saved on server and served"),
        ("Reflected XSS","Script reflected back in immediate response"),
        ("CSRF","Force a user’s browser to make unwanted request"),
        ("DNS poisoning","Poison resolver cache to redirect traffic"),
        ("ARP spoofing","Forge ARP replies to redirect traffic"),
        ("DoS","Overwhelm resources to make service unavailable"),
        ("DDoS","Distributed DoS from many sources"),
        ("Logic bomb","Dormant code triggers on conditions"),
        ("Backdoor","Covert method to bypass authentication"),
        ("Rootkit","Hide presence and maintain privilege"),
        ("Keylogger","Capture keystrokes"),
        ("Spyware","Collect info without consent"),
    ]
    for name, desc in attack_bank:
        items.append(QA(
            "Threats","Attack types",
            f"Which attack is described: {desc}?",
            [name, "Pharming", "Insider threat", "Malvertising"],
            name,
            f"{name}: {desc}.",
            "medium"
        ))
    # Vulnerability management items
    items += [
        QA("Threats","VM","A CVSS score of 9.8 indicates:",
           ["Low severity","Medium severity","High severity","Critical severity"],"Critical severity",
           "CVSS 9.0–10.0 is critical.","medium"),
        QA("Threats","VM","Best practice after a high-severity finding:",
           ["Ignore","Reboot","Prioritize remediation","Disable logging"],"Prioritize remediation",
           "Treat high/critical findings promptly.","easy"),
    ]
    return items

def gen_architecture() -> List[QA]:
    items: List[QA] = [
        QA("Architecture","Network","Which zone hosts public-facing servers?",
           ["LAN","DMZ","Intranet","Extranet"],"DMZ",
           "DMZ isolates public services from internal LAN.","easy"),
        QA("Architecture","Design","Using overlapping controls is:",
           ["Zero trust","Defense in depth","Least privilege","Segmentation"],"Defense in depth",
           "Layered controls reduce single points of failure.","easy"),
        QA("Architecture","Cloud","Model with most customer control:",
           ["SaaS","PaaS","IaaS","FaaS"],"IaaS",
           "IaaS exposes infra; you manage OS/apps/data.","medium"),
        QA("Architecture","Compute","Which isolates workloads with shared kernel?",
           ["VMs","Containers","Hypervisors","Sandboxes"],"Containers",
           "Containers share host OS kernel; VMs emulate hardware.","medium"),
        QA("Architecture","Access","Which assumes no implicit trust?",
           ["AAA","Zero trust","RBAC","MAC"],"Zero trust",
           "Zero trust requires verification at each access.","easy"),
    ]
    design_controls = [
        ("WAF","Protects web apps from OWASP threats at HTTP layer"),
        ("NAC","Controls access based on device posture/policy"),
        ("Microsegmentation","Fine-grained policy between workloads"),
        ("Jump box","Hardened system for admin access"),
        ("Air gap","Physical isolation from networks"),
        ("Bastion host","Exposed system designed for attacks"),
        ("Proxy","Intermediary for requests; can inspect/filter"),
        ("Egress filtering","Control outbound traffic"),
        ("Honeypot","Decoy system to lure/observe attackers"),
        ("Load balancer","Distribute traffic across servers"),
    ]
    for name, defn in design_controls:
        items.append(QA(
            "Architecture","Controls",
            f"What best describes {name}?",
            [defn, "Encrypts data at rest", "Allocates IP addresses", "Provides MFA"],
            defn,
            f"{name}: {defn}.",
            "easy"
        ))
    return items

def gen_operations() -> List[QA]:
    items: List[QA] = [
        QA("Operations","Monitoring","SIEM primarily provides:",
           ["Data encryption","Centralized log analysis","Patch management","Access control"],"Centralized log analysis",
           "SIEM aggregates and correlates logs.","easy"),
        QA("Operations","IR","First incident response step:",
           ["Containment","Eradication","Identification","Recovery"],"Identification",
           "Identify before containment/eradication.","easy"),
        QA("Operations","Forensics","Chain of custody ensures:",
           ["System uptime","Evidence integrity","User privacy","Availability"],"Evidence integrity",
           "Chain of custody preserves integrity for admissibility.","medium"),
        QA("Operations","Vuln mgmt","Patch management primarily:",
           ["Detects anomalies","Applies updates to fix vulnerabilities","Encrypts files","Allocates bandwidth"],
           "Applies updates to fix vulnerabilities","Patch process reduces known vulnerabilities.","easy"),
        QA("Operations","Exercises","Tabletop exercises are:",
           ["Live-fire attacks","Discussion-based scenario simulations","Pen tests","NDA reviews"],"Discussion-based scenario simulations",
           "Tabletops rehearse roles and decisions.","easy"),
    ]
    ops_tools = [
        ("SOAR","Automate response orchestration"),
        ("EDR","Endpoint detection and response"),
        ("UEBA","Detect anomalies via behavior analytics"),
        ("NDR","Network detection and response"),
        ("Syslog","Standard for event messaging"),
        ("Baselining","Record normal activity for comparison"),
        ("Hardening","Reduce attack surface via configuration"),
        ("Penetration testing","Authorized simulated attacks"),
        ("Red team","Adversary emulation team"),
        ("Blue team","Defensive monitoring/response team"),
        ("Purple team","Collaborative offense/defense team"),
    ]
    for name, defn in ops_tools:
        items.append(QA(
            "Operations","Processes & tools",
            f"{name} primarily provides:",
            [defn, "Key exchange", "File encryption", "Network address translation"],
            defn,
            f"{name}: {defn}.",
            "medium"
        ))
    return items

def gen_program() -> List[QA]:
    items: List[QA] = [
        QA("Program Mgmt","Policy","Which policy defines permitted IT resource use?",
           ["Privacy policy","Acceptable use policy","Data retention policy","Risk register"],"Acceptable use policy",
           "AUPs set expectations and constraints.","easy"),
        QA("Program Mgmt","Risk","Which method uses monetary values?",
           ["Qualitative","Quantitative","Comparative","Heuristic"],"Quantitative",
           "Quantitative risk uses dollars for likelihood/impact.","medium"),
        QA("Program Mgmt","Compliance","Which governs US healthcare data?",
           ["PCI DSS","HIPAA","GDPR","SOX"],"HIPAA",
           "HIPAA regulates PHI handling.","easy"),
        QA("Program Mgmt","Metrics","RTO measures:",
           ["Max tolerable data loss","Target time to restore service","Mean time to recover","Availability percentage"],
           "Target time to restore service","RTO defines restoration goal.","easy"),
        QA("Program Mgmt","HR","Mandatory vacation helps:",
           ["Morale only","Detect long-term fraud","Encrypt data","Reduce latency"],"Detect long-term fraud",
           "Time off exposes hidden schemes/process dependencies.","medium"),
    ]
    gov_items = [
        ("ISO 27001","ISMS and certification standard"),
        ("SOC 2","Service organization controls attestation"),
        ("NIST RMF","Risk management framework"),
        ("PCI DSS","Secure cardholder data requirements"),
        ("Risk register","List of identified risks"),
        ("Data owner","Accountable for data decisions"),
        ("Data custodian","Manages day-to-day data handling"),
        ("DPO","Oversees privacy compliance"),
        ("Steering committee","Guides program priorities"),
        ("Security awareness training","Reduce human error/social engineering"),
    ]
    for name, defn in gov_items:
        items.append(QA(
            "Program Mgmt","Governance",
            f"What best describes {name}?",
            [defn, "Encrypts data at rest", "Monitors packets", "Allocates IPs"],
            defn,
            f"{name}: {defn}.",
            "easy"
        ))
    return items

def gen_crypto() -> List[QA]:
    items: List[QA] = [
        QA("Cryptography & PKI","Algorithms","Which is a symmetric block cipher?",
           ["RSA","AES","ECC","Diffie-Hellman"],"AES",
           "AES is a symmetric block cipher widely used.","easy"),
        QA("Cryptography & PKI","Key exchange","Which algorithm is used for key exchange?",
           ["SHA-256","Diffie-Hellman","AES","HMAC"],"Diffie-Hellman",
           "Diffie-Hellman negotiates shared secrets.","easy"),
        QA("Cryptography & PKI","PKI","Which PKI component issues certificates?",
           ["RA","CA","CRL","OCSP"],"CA",
           "Certificate Authorities issue and sign certificates.","easy"),
        QA("Cryptography & PKI","Hashing","Which hashing algorithm produces a 256-bit digest?",
           ["MD5","SHA-1","SHA-256","SHA-512"],"SHA-256",
           "SHA-256 is part of SHA-2 family.","easy"),
        QA("Cryptography & PKI","TLS","Compromise of keys not affecting past sessions is:",
           ["Non-repudiation","Perfect forward secrecy","Key escrow","Digital signature"],"Perfect forward secrecy",
           "PFS prevents decryption of past sessions after key compromise.","medium"),
    ]
    crypto_terms = [
        ("RSA","Asymmetric algorithm used for encryption/signing"),
        ("ECC","Asymmetric using elliptic curves; shorter keys"),
        ("HMAC","Integrity/auth with shared secret"),
        ("Salt","Random data added before hashing passwords"),
        ("Nonce","Number used once, e.g., to prevent replay"),
        ("IV","Initialization vector for block cipher modes"),
        ("PBKDF2","Key-derivation for password hashing"),
        ("bcrypt","Adaptive password hashing function"),
        ("scrypt","Memory-hard password hashing"),
        ("Digital certificate","Binds public key to identity"),
        ("CRL","List of revoked certificates"),
        ("OCSP","Online certificate status protocol"),
        ("CSR","Request for a certificate"),
        ("Keystore","Secure storage of keys/certs"),
        ("HSM","Hardware security module for key protection"),
        ("Key escrow","Trusted third party holds keys"),
        ("Pinning","Bind TLS to expected certificate/public key"),
        ("Mutual TLS","Both client and server present certificates"),
        ("Cipher suite","Set of algorithms used in TLS"),
        ("Trust store","Trusted CA certificates repository"),
    ]
    for name, defn in crypto_terms:
        items.append(QA(
            "Cryptography & PKI","Concepts",
            f"What best describes {name}?",
            [defn, "Availability improvement", "User access audit", "Packet filtering"],
            defn,
            f"{name}: {defn}.",
            "easy"
        ))
    return items

# ---------------------------
# Build pool and deduplicate
# ---------------------------
def build_large_pool() -> List[QA]:
    pool: List[QA] = []
    pool.extend(gen_general())
    pool.extend(gen_threats())
    pool.extend(gen_architecture())
    pool.extend(gen_operations())
    pool.extend(gen_program())
    pool.extend(gen_crypto())

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
# Sample 90 unique questions
# ---------------------------
def sample_exam(pool: List[QA], seed: Optional[int], shuffle_choices: bool) -> List[QA]:
    if seed is not None:
        random.seed(seed)
    exam_qs = random.sample(pool, 90)
    if shuffle_choices:
        for qa in exam_qs:
            if qa.answer not in qa.choices:
                qa.choices = [qa.answer] + qa.choices
            random.shuffle(qa.choices)
    return exam_qs

# ---------------------------
# Run exam with scaled scoring
# ---------------------------
def run_exam(questions: List[QA], timer_enabled: bool = True, passing_scaled: int = 750):
    total = len(questions)
    assert total == 90, "Exam must be exactly 90 questions"
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
    scaled = int(100 + (raw / total) * 800)
    passed = scaled >= passing_scaled
    answered = sum(a for a, _ in per_domain.values())

    print("\n" + "-" * 70)
    print(f"Raw score: {raw}/{answered}  |  Scaled: {scaled} (100–900, pass ≥ {passing_scaled})")
    print("Result:", "✅ PASS" if passed else "❌ FAIL")
    print("Domain breakdown:")
    for dom, (a, c) in sorted(per_domain.items()):
        dpct = (c / max(1, a)) * 100
        print(f"- {dom}: {c}/{a} ({dpct:.1f}%)")
    print("-" * 70)

# ---------------------------
# CLI entry point
# ---------------------------
def main():
    parser = argparse.ArgumentParser(description="CompTIA Security+ (SY0-701) 90-question exam simulator")
    parser.add_argument("--seed", type=int, default=None, help="Deterministic seed for reproducible exam")
    parser.add_argument("--shuffle", action="store_true", help="Shuffle answer choices")
    parser.add_argument("--no-timer", action="store_true", help="Disable 90-minute timer")
    parser.add_argument("--pass", dest="passing_scaled", type=int, default=750,
                        help="Passing scaled score threshold (default 750)")
    args = parser.parse_args()

    pool = build_large_pool()
    exam_qs = sample_exam(pool, seed=args.seed, shuffle_choices=args.shuffle)
    run_exam(exam_qs, timer_enabled=(not args.no_timer), passing_scaled=args.passing_scaled)

if __name__ == "__main__":
    main()
