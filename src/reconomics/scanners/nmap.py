import shutil
import subprocess
import xml.etree.ElementTree as ET

from reconomics.models import HostFinding, ScanResult, ServiceFinding
from reconomics.scanners.base import Scanner
from reconomics.targets import TargetType

class NmapError(RuntimeError):
    pass


class NmapScanner(Scanner):
    supported_target_types = {
    TargetType.IP,
    TargetType.NETWORK,
    TargetType.DOMAIN,
    }
    def __init__(self, executable: str = "nmap", timeout: int = 300):
        self.executable = executable
        self.timeout = timeout

    def scan(self, target: str):
        if shutil.which(self.executable) is None:
            raise NmapError(
                f"Nmap executable not found: {self.executable}"
            )

        command = [
            self.executable,
            "-sV",
            "-oX",
            "-",
            target,
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )

        except subprocess.TimeoutExpired as exc:
            raise NmapError(
                f"Nmap scan timed out after {self.timeout} seconds"
            ) from exc

        if result.returncode != 0:
            raise NmapError(
                result.stderr.strip() or "Nmap scan failed"
            )

        return self.parse_xml(target, result.stdout)

    @staticmethod
    def parse_xml(target: str, xml_text: str) -> ScanResult:
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            raise NmapError(
                f"Unable to parse Nmap XML: {exc}"
            ) from exc

        scan_result = ScanResult(
            scanner="nmap",
            target=target,
        )

        for host_node in root.findall("host"):
            address_node = host_node.find("address")

            if address_node is None:
                continue

            address = address_node.get("addr")

            if not address:
                continue

            status_node = host_node.find("status")
            hostname_node = host_node.find("./hostnames/hostname")

            host = HostFinding(
                address=address,
                status=(
                    status_node.get("state")
                    if status_node is not None
                    else None
                ),
                hostname=(
                    hostname_node.get("name")
                    if hostname_node is not None
                    else None
                ),
            )

            for port_node in host_node.findall("./ports/port"):
                state_node = port_node.find("state")

                if state_node is None:
                    continue

                service_node = port_node.find("service")

                service = ServiceFinding(
                    port=int(port_node.get("portid")),
                    protocol=port_node.get(
                        "protocol",
                        "tcp",
                    ),
                    state=state_node.get(
                        "state",
                        "unknown",
                    ),
                    service=(
                        service_node.get("name")
                        if service_node is not None
                        else None
                    ),
                    product=(
                        service_node.get("product")
                        if service_node is not None
                        else None
                    ),
                    version=(
                        service_node.get("version")
                        if service_node is not None
                        else None
                    ),
                )

                host.services.append(service)

            scan_result.hosts.append(host)

        return scan_result
