import json
import shutil
import subprocess
from pathlib import Path

from reconomics.models import ScanResult
from reconomics.scanners.base import Scanner


def get_system_resolvers() -> list[str]:
    resolv_conf = Path("/etc/resolv.conf")

    if not resolv_conf.exists():
        return []

    resolvers = []

    for line in resolv_conf.read_text(
        encoding="utf-8",
    ).splitlines():
        line = line.strip()

        if not line.startswith("nameserver "):
            continue

        _, address = line.split(
            maxsplit=1,
        )

        resolvers.append(
            address.strip()
        )

    return resolvers

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

        resolvers = get_system_resolvers()

        if resolvers:
            command.extend(
                [
                    "-r",
                    ",".join(resolvers),
                ]
            )

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