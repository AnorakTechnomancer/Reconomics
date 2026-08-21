import json
import logging
import shutil
import subprocess
import tempfile

from reconomics.config import get_api_key
from reconomics.models import VulnerabilityFinding, WordPressFinding

logger = logging.getLogger(__name__)

class WPScanError(RuntimeError):
    pass


class WPScanScanner:
    def __init__(
        self,
        executable: str = "wpscan",
        timeout: int = 600,
    ) -> None:
        self.executable = executable
        self.timeout = timeout
        token = get_api_key(
            "wpscan",
            "api_token",
        )

        self.api_token = (
            token.strip()
            if token and token.strip()
            else None
        )



    def parse_output(
        self,
        data: dict,
        url: str,
    ) -> WordPressFinding:
        version = None

        if data.get("version"):
            version = data["version"].get("number")

        plugins = list(
            (data.get("plugins") or {}).keys()
        )

        themes = []

        if data.get("main_theme"):
            slug = data["main_theme"].get("slug")

            if slug:
                themes.append(slug)

        vulnerabilities = []

        for vuln in (data.get("version") or {}).get(
            "vulnerabilities",
            [],
        ):
            title = vuln.get("title")

            if title:
                vulnerabilities.append(
                    VulnerabilityFinding(
                        title=title,
                        fixed_in=vuln.get("fixed_in"),
                        references=[
                            str(reference)
                            for values in (vuln.get("references") or {}).values()
                            for reference in (
                                values if isinstance(values, list) else [values]
                            )
                        ],
                    )
                )

        for plugin_data in (data.get("plugins") or {}).values():
            for vuln in plugin_data.get(
                "vulnerabilities",
                [],
            ):
                title = vuln.get("title")

                if title:
                    vulnerabilities.append(
                        VulnerabilityFinding(
                            title=title,
                            fixed_in=vuln.get("fixed_in"),
                            references=[
                                str(reference)
                                for values in (vuln.get("references") or {}).values()
                                for reference in (
                                    values if isinstance(values, list) else [values]
                                )
                            ],
                        )
                    )

        return WordPressFinding(
            url=url,
            version=version,
            plugins=plugins,
            themes=themes,
            vulnerabilities=vulnerabilities,
        )

    def scan_url(self, url: str) -> WordPressFinding:
        if shutil.which(self.executable) is None:
            raise WPScanError(
                f"WPScan executable not found: {self.executable}"
            )

        with tempfile.NamedTemporaryFile(
            suffix=".json",
            delete=False,
        ) as output_file:
            output_path = output_file.name

        logger.info(
            "WPScan API token configured: %s",
            bool(self.api_token),
)

        command = [
            self.executable,
            "--url",
            url,
            "--format",
            "json",
            "--output",
            output_path,
            "--no-banner",
            "--random-user-agent",
        ]

        if self.api_token:
            command.extend(
                [
                    "--api-token",
                    self.api_token,
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
            raise WPScanError(
                f"WPScan timed out after {self.timeout} seconds"
            ) from exc

        data = {}

        try:
            with open(
                output_path,
                encoding="utf-8",
            ) as file:
                data = json.load(file)

        except (OSError, json.JSONDecodeError):
            pass

        if result.returncode != 0:
            error_message = (
                data.get("scan_aborted")
                or result.stderr.strip()
                or result.stdout.strip()
                or (
                    "WPScan exited with code "
                    f"{result.returncode}"
                )
            )

            raise WPScanError(
                error_message
            )

        return self.parse_output(
            data,
            url,
        )