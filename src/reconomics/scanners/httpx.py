import json
import shutil
import subprocess

from reconomics.models import ScanResult
from reconomics.scanners.base import Scanner


class HttpxError(RuntimeError):
    pass


class HttpxScanner(Scanner):
    def __init__(
        self,
        executable: str = "httpx",
        timeout: int = 300,
    ) -> None:
        self.executable = executable
        self.timeout = timeout

    def scan_url(self, url: str) -> dict:
        if shutil.which(self.executable) is None:
            raise HttpxError(
                f"httpx executable not found: {self.executable}"
            )

        command = [
            self.executable,
            "-u",
            url,
            "-json",
            "-silent",
            "-title",
            "-status-code",
            "-tech-detect",
            "-follow-redirects"
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
            raise HttpxError(
                f"httpx timed out after {self.timeout} seconds"
            ) from exc

        if result.returncode != 0:
            raise HttpxError(
                result.stderr.strip() or "httpx scan failed"
            )

        lines = [
            line
            for line in result.stdout.splitlines()
            if line.strip()
        ]

        if not lines:
            return {}

        return json.loads(lines[0])

    def scan(self, target: str) -> ScanResult:
        raise NotImplementedError(
            "Use scan_url() for web-service enrichment."
        )