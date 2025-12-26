import ipaddress



def validate_ipv4(ip: str) -> str:
    try:
        ipaddress.IPv4Address(ip)
        return ip
    except ValueError:
        raise ValueError("Invalid IPv4 address")

def validate_port(port: str) -> int:
    if not port.isdigit():
        raise ValueError("Port must be numeric")

    port = int(port)
    if not (1 <= port <= 65535):
        raise ValueError("Port must be between 1 and 65535")

    return port

COMMON_PORTS_TOP_100 = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123,
    137, 138, 139, 143, 161, 162, 179, 389, 443, 445, 465,
    500, 514, 515, 520, 587, 636, 989, 990, 993, 995,
    1433, 1521, 2049, 2082, 2083, 2086, 2087,
    2095, 2096, 2181, 2222, 2483, 2484,
    3000, 3306, 3389, 3690, 4444, 5432,
    5900, 5984, 6379, 6666, 7001, 7002,
    8080, 8081, 8443, 8888, 9200, 27017
]

def parse_ports(value: str) -> list[int]:
    value = value.strip().lower()

    if value == "top100":
        return COMMON_PORTS_TOP_100

    if "-" in value:
        start, end = value.split("-", 1)
        start, end = int(start), int(end)

        if not (0 <= start <= 65535 and 0 <= end <= 65535):
            raise ValueError("Port range must be between 0 and 65535")

        if start > end:
            raise ValueError("Invalid range: start > end")

        return list(range(start, end + 1))

    # single port
    port = int(value)
    if not (1 <= port <= 65535):
        raise ValueError("Port must be between 1 and 65535")

    return [port]
