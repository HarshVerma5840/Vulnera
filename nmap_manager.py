import nmap
from urllib.parse import urlparse

scanner = nmap.PortScanner(
    nmap_search_path=(
        r"C:\Program Files (x86)\Nmap\nmap.exe",
    )
)

def clean_target(target):
    """
    Converts URL to hostname if user enters:
    https://example.com
    http://example.com
    """

    if "://" in target:
        return urlparse(target).hostname

    return target


def scan_host(target):
    target = clean_target(target)
    scanner.scan(
        target,
        ports="21,22,23,25,53,80,110,143,443,445,3306,3389,8080",
        arguments="-sV"
    )
    results = []

    for host in scanner.all_hosts():
        host_data = {
            "host": host,
            "state": scanner[host].state(),
            "ports": []
        }

        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                port_info = scanner[host][proto][port]
                host_data["ports"].append({
                    "port": port,
                    "state": port_info.get("state", ""),
                    "service": port_info.get("name", ""),
                    "product": port_info.get("product", ""),
                    "version": port_info.get("version", "")
                })

        results.append(host_data)

    return results
