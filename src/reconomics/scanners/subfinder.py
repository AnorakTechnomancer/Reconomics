import json
import shutil
import subprocess

from reconomics.models import DomainFinding, ScanResult
from reconomics.scanners.base import Scanner
from reconomics.targets import TargetType


class SubfinderError(RuntimeError):
    pass


class SubfinderScanner(Scanner):
    supported_target_types = {
        TargetType.DOMAIN,
    }
    def __init__(
        self,
        executable: str = "subfinder",
        timeout: int = 300,
    ):
        self.executable = executable
        self.timeout = timeout

    def scan(self, target: str) -> ScanResult:
        if shutil.which(self.executable) is None:
            raise SubfinderError(
                f"Subfinder executable not found: {self.executable}"
            )

        command = [
            self.executable,
            "-d",
            target,
            "-json",
            "-silent",
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
            raise SubfinderError(
                f"Subfinder timed out after {self.timeout} seconds"
            ) from exc

        if result.returncode != 0:
            raise SubfinderError(
                result.stderr.strip() or "Subfinder scan failed"
            )

        return self.parse_output(
            target,
            result.stdout,
        )

    @staticmethod
    def parse_output(
        target: str,
        output: str,
    ) -> ScanResult:
        scan_result = ScanResult(
            scanner="subfinder",
            target=target,
        )

        for line in output.splitlines():
            if not line.strip():
                continue

            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            hostname = item.get("host")

            if not hostname:
                continue

            scan_result.domains.append(
                DomainFinding(
                    name=hostname,
                    source=item.get("source"),
                )
            )

        return scan_result