from app.Scanner import Scanner
from utils import validate_ipv4, parse_ports

DEFAULT_DECOYS = [
    "8.8.8.8",
    "1.1.1.1",
    "192.168.1.1",
    "10.0.0.1"
]

def main():
    try:
        ip = validate_ipv4(input("Target IP: ").strip())

        print("\n=== Port Selection ===")
        print("1) Single port")
        print("2) Top 100 common ports")
        print("3) Custom range (ex: 80-100 or 0-2000)")

        port_choice = input("Select an option: ").strip()

        match port_choice:
            case "1":
                ports = parse_ports(input("Port: ").strip())

            case "2":
                ports = parse_ports("top100")

            case "3":
                ports = parse_ports(input("Range: ").strip())

            case _:
                raise ValueError("Invalid port selection")

        scanner = Scanner(ip_target=ip, ports=ports)

        while True:
            print("\n=== Port Scanner Menu ===")
            print("1) TCP SYN scan")
            print("2) TCP ACK scan")
            print("3) UDP scan")
            print("4) TCP SYN Decoy scan")
            print("0) Exit")

            choice = input("Select an option: ").strip()

            match choice:
                case "1":
                    result = scanner.tcp_syn_scan()
                    print("[*] TCP SYN scan result:")
                    for port, status in result.items():
                        print(f"  {port}: {status}")

                case "2":
                    result = scanner.ack_scan()
                    print("[*] TCP ACK scan result:")
                    for port, status in result.items():
                        print(f"  {port}: {status}")

                case "3":
                    result = scanner.udp_scan()
                    print("[*] UDP scan result:")
                    for port, status in result.items():
                        print(f"  {port}: {status}")

                case "4":
                    print("\nDecoy options:")
                    print("1) Use predefined decoys")
                    print("2) Custom decoys")

                    decoy_choice = input("Select an option: ").strip()

                    match decoy_choice:
                        case "1":
                            scanner.decoys = DEFAULT_DECOYS
                            print(f"[+] Using predefined decoys: {', '.join(scanner.decoys)}")

                        case "2":
                            decoys = input(
                                "Enter decoy IPs separated by comma: "
                            ).split(",")

                            scanner.decoys = [d.strip() for d in decoys if d.strip()]

                        case _:
                            print("[!] Invalid decoy option")
                            continue

                    result = scanner.tcp_syn_scan_decoy()
                    print("[*] TCP SYN Decoy scan result:")
                    for port, status in result.items():
                        print(f"  {port}: {status}")

                case "0":
                    print("[+] Exiting...")
                    break

                case _:
                    print("[!] Invalid option")

    except ValueError as e:
        print(f"[!] Invalid input: {e}")

    except PermissionError:
        print("[!] Permission denied. Run as root (sudo).")

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")

    except Exception as e:
        print(f"[!] Unexpected error: {e}")


if __name__ == "__main__":
    main()
