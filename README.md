# Python Port Scanner (TCP & UDP) — Theory-Based Implementation

This project is a **Port Scanner** written in Python using **Scapy** and OO.

---

## Protocol Background (Theory)

### TCP (Transmission Control Protocol)

TCP is a **connection-oriented** protocol that uses a **three-way handshake**:

1. **SYN** → request to start a connection
2. **SYN-ACK** → server accepts
3. **ACK** → connection established

TCP has **flags** that indicate connection state:

* `S` → SYN
* `A` → ACK
* `R` → RST (Reset)
* `F` → FIN (Close)

Because TCP is stateful, **port scanning relies on how servers respond to invalid or partial handshakes**.

---

### UDP (User Datagram Protocol)

UDP is **connectionless**:

* No handshake
* No session state
* No ACKs

UDP scanning relies mostly on **ICMP messages**, not UDP replies.

---

## Implemented Scan Techniques

### 1️⃣ TCP SYN Scan (Half-Open Scan)

**Function:** `tcp_syn_scan()`

#### Theory

This scan sends only the **first packet of the TCP handshake** (`SYN`) and analyzes the response.

| Response    | Meaning                 |
| ----------- | ----------------------- |
| SYN-ACK     | Port is **open**        |
| RST         | Port is **closed**      |
| No response | **Filtered** (firewall) |

The connection is **never fully established**, making it stealthier.

#### TCP Flow

```
Scanner → SYN
Target  → SYN-ACK  (open)
Target  → RST      (closed)
```

#### Code Logic

```python
pkt = IP(dst=ip_target) / TCP(dport=port, flags="S")
resp = sr1(pkt, timeout=TIMEOUT)
```

---

### 2️⃣ TCP ACK Scan (Firewall Detection)

**Function:** `ack_scan()`

#### Theory

This scan does **not** determine if a port is open or closed.

Instead, it checks **firewall rules** by sending an **out-of-context ACK** packet.

| Response    | Meaning                |
| ----------- | ---------------------- |
| RST         | Port is **unfiltered** |
| No response | **Filtered**           |

Why?
Because a host **must reply with RST** to an invalid ACK **unless a firewall blocks it**.

#### TCP Flow

```
Scanner → ACK
Target  → RST   (no firewall)
(no reply)      (firewall)
```

---

### 3️⃣ UDP Scan

**Function:** `udp_scan()`

#### Theory

UDP does not acknowledge packets.
Therefore, **silence often means open**.

The only reliable signal comes from **ICMP errors**.

| Response           | Meaning              |
| ------------------ | -------------------- |
| UDP reply          | **Open**             |
| ICMP type 3 code 3 | **Closed**           |
| No response        | **Open or Filtered** |

#### ICMP Explanation

* `Type 3` → Destination Unreachable
* `Code 3` → Port Unreachable

This means:

> “The host exists, but nothing listens on that port.”

---

### 4️⃣ TCP SYN Scan with Decoys (IDS Evasion)

**Function:** `tcp_syn_scan_decoy()`

#### Theory

This technique sends **multiple SYN packets**:

* Several from **fake source IPs (decoys)**
* One from the **real scanner IP**

To the target and its logs, **all IPs look identical**.

#### TCP Flow

```
Decoy IP 1 → SYN
Decoy IP 2 → SYN
Decoy IP 3 → SYN
Real IP    → SYN  ← response analyzed
```

Only the **real IP waits for the response**.

---

#### Why it works

* IDS/IPS logs show multiple attackers
* Makes attribution harder
* Same principle used by `nmap -D`

#### Limitations

* Requires root
* Fails if network blocks IP spoofing
* Modern IDS may detect timing patterns

---

## 🧬 Response Interpretation Summary

| Scan Type | Packet Sent | Response | Interpretation  |
| --------- | ----------- | -------- | --------------- |
| SYN       | SYN         | SYN-ACK  | Open            |
| SYN       | SYN         | RST      | Closed          |
| SYN       | SYN         | None     | Filtered        |
| ACK       | ACK         | RST      | Unfiltered      |
| ACK       | ACK         | None     | Filtered        |
| UDP       | UDP         | UDP      | Open            |
| UDP       | UDP         | ICMP 3/3 | Closed          |
| UDP       | UDP         | None     | Open / Filtered |

---

## 🛠️ Requirements

* Python 3.x
* Scapy
* Root privileges (raw sockets)

```bash
pip install scapy
sudo python3 main.py
```

---

## 🚀 Example Usage

```python
ip = "192.168.3.22"
port = 9000

print("SYN scan:", tcp_syn_scan(ip, port))
print("ACK scan:", ack_scan(ip, port))
print("UDP scan:", udp_scan(ip, port))
print(
    "SYN decoy scan:",
    tcp_syn_scan_decoy(
        ip,
        port,
        decoys=["10.0.0.5", "172.16.0.9", "192.168.1.100"]
    )
)
```















































Port range and top ports
dns translator