import sys
from urllib.parse import urlparse


def clean_target(target):
    """
    Converts URL to hostname if user enters:
    https://example.com
    http://example.com
    """

    if "://" in target:
        return urlparse(target).hostname

    return target


def _get_scanner():
    """Lazily import the third-party python-nmap library to avoid
    circular import with this project's own nmap/ package."""
    import importlib
    import pathlib

    # Find the real python-nmap package in site-packages
    real_nmap_path = None
    for path_str in sys.path:
        candidate = pathlib.Path(path_str) / "nmap" / "__init__.py"
        if candidate.exists() and "site-packages" in str(candidate):
            real_nmap_path = str(candidate.parent)
            break

    if real_nmap_path is None:
        raise ImportError("python-nmap library not found. Install with: pip install python-nmap")

    # Save and remove our project's nmap from sys.modules
    saved = {}
    for key in list(sys.modules.keys()):
        if key == "nmap" or key.startswith("nmap."):
            saved[key] = sys.modules.pop(key)

    # Temporarily put the real site-packages path first
    sys.path.insert(0, real_nmap_path.rsplit("nmap", 1)[0])
    try:
        import nmap as real_nmap
        scanner = real_nmap.PortScanner(
            nmap_search_path=(
                r"C:\Program Files (x86)\Nmap\nmap.exe",
            )
        )
        return scanner
    finally:
        # Clean up: remove the real nmap from sys.modules and restore ours
        for key in list(sys.modules.keys()):
            if key == "nmap" or key.startswith("nmap."):
                del sys.modules[key]
        sys.modules.update(saved)
        # Remove the path we inserted
        try:
            sys.path.remove(real_nmap_path.rsplit("nmap", 1)[0])
        except ValueError:
            pass


def scan_host(target):
    scanner = _get_scanner()
    target = clean_target(target)
    scanner.scan(
        target,
        arguments="-T4 --top-ports 1000 -sV"
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

