import json
import shutil
import subprocess

from reconomics.models import SecurityFinding
from reconomics.scanners.httpx import get_system_resolvers


class NucleiError(RuntimeError):
    pass


class NucleiScanner:
    def __init__(
        self,
        executable: str = "nuclei",
        timeout: int = 900,
    ) -> None:
        self.executable = executable
        self.timeout = timeout

    def parse_output(
        self,
        output: str,
    ) -> list[SecurityFinding]:
        findings = []

        for line in output.splitlines():
            if not line.strip():
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = data.get("info") or {}

            finding = SecurityFinding(
                title=info.get("name", "Unknown finding"),
                severity=info.get("severity", "unknown"),
                discovered_by=["nuclei"],
                affected_asset=(
                    data.get("matched-at")
                    or data.get("host")
                    or data.get("url")
                    or "unknown"
                ),
                description=info.get("description"),
                matched_at=data.get("matched-at"),
                template_id=data.get("template-id"),
                tags=info.get("tags") or [],
                references=info.get("reference") or [],
            )

            findings.append(finding)

        return findings

    def scan_url(
        self,
        url: str,
    ) -> list[SecurityFinding]:
        if shutil.which(self.executable) is None:
            raise NucleiError(
                f"Nuclei executable not found: {self.executable}"
            )

        command = [
            self.executable,
            "-u",
            url,
            "-jsonl",
            "-silent",
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
            raise NucleiError(
                f"Nuclei timed out after {self.timeout} seconds"
            ) from exc

        if result.returncode != 0:
            raise NucleiError(
                result.stderr.strip()
                or "Nuclei scan failed"
            )

        return self.parse_output(result.stdout)