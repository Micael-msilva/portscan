from scapy.all import IP, TCP, UDP, ICMP, sr1, send

class Scanner:
    TIMEOUT = 1

    def __init__(self, ip_target, ports, decoys=None):
        if not ip_target:
            raise ValueError("Target IP is required")

        if not isinstance(ports, (list, tuple)) or not ports:
            raise ValueError("Ports must be a non-empty list")

        for port in ports:
            if not isinstance(port, int) or not (0 <= port <= 65535):
                raise ValueError(f"Invalid port: {port}")

        self.ip = ip_target
        self.ports = ports
        self.decoys = decoys or []


    def tcp_syn_scan(self):
        results = {}

        for port in self.ports:
            pkt = IP(dst=self.ip) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=self.TIMEOUT, verbose=False)

            if resp is None:
                results[port] = "filtered"
                continue

            if resp.haslayer(TCP):
                flags = resp[TCP].flags
                if flags == "SA":
                    results[port] = "open"
                elif flags in ("RA", "R"):
                    results[port] = "closed"
                else:
                    results[port] = "unknown"
            else:
                results[port] = "unknown"

        return results


    def ack_scan(self):
        results = {}

        for port in self.ports:
            pkt = IP(dst=self.ip) / TCP(dport=port, flags="A")
            resp = sr1(pkt, timeout=self.TIMEOUT, verbose=False)

            if resp is None:
                results[port] = "filtered"
                continue

            if resp.haslayer(TCP):
                flags = resp[TCP].flags
                if flags in ("RA", "R"):
                    results[port] = "unfiltered"
                else:
                    results[port] = "unknown"
            else:
                results[port] = "unknown"

        return results

    def udp_scan(self):
        results = {}

        for port in self.ports:
            pkt = IP(dst=self.ip) / UDP(dport=port)
            resp = sr1(pkt, timeout=self.TIMEOUT, verbose=False)

            if resp is None:
                results[port] = "open|filtered"
                continue

            if resp.haslayer(UDP):
                results[port] = "open"
                continue

            if resp.haslayer(ICMP):
                if resp[ICMP].type == 3 and resp[ICMP].code == 3:
                    results[port] = "closed"
                else:
                    results[port] = "filtered"
                continue

            results[port] = "unknown"

        return results

    def tcp_syn_scan_decoy(self):
        if not self.decoys:
            raise ValueError("Decoy list is empty")

        results = {}

        for port in self.ports:
            # fire-and-forget decoys
            for decoy_ip in self.decoys:
                decoy_pkt = IP(src=decoy_ip, dst=self.ip) / TCP(
                    dport=port, flags="S"
                )
                send(decoy_pkt, verbose=False)

            # real packet
            real_pkt = IP(dst=self.ip) / TCP(dport=port, flags="S")
            resp = sr1(real_pkt, timeout=self.TIMEOUT, verbose=False)

            if resp is None:
                results[port] = "filtered"
                continue

            if resp.haslayer(TCP):
                flags = resp[TCP].flags
                if flags == "SA":
                    results[port] = "open"
                elif flags in ("RA", "R"):
                    results[port] = "closed"
                else:
                    results[port] = "unknown"
            else:
                results[port] = "unknown"

        return results
