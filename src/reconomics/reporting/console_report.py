from rich.console import Console
from rich.table import Table

from reconomics.models import AssetType, ScanSession

console = Console()


def render_console(session: ScanSession) -> None:
    console.rule("[bold]Reconomics")

    console.print(f"[bold]Target:[/bold] {session.target}")

    domain_count = sum(
        1
        for asset in session.assets
        if asset.asset_type == AssetType.DOMAIN
    )

    ip_count = sum(
        1
        for asset in session.assets
        if asset.asset_type == AssetType.IP
    )

    service_count = sum(
        len(host.services)
        for result in session.scanner_results
        for host in result.hosts
    )

    web_endpoint_count = sum(
        1
        for asset in session.assets
        if asset.asset_type == AssetType.WEB_ENDPOINT
    )

    finding_count = len(
        session.security_findings
    )

    critical_count = sum(
        1
        for finding in session.security_findings
        if finding.severity.lower() == "critical"
    )

    high_count = sum(
        1
        for finding in session.security_findings
        if finding.severity.lower() == "high"
    )

    summary = Table(title="Scan Summary")
    summary.add_column("Metric")
    summary.add_column("Count", justify="right")

    summary.add_row("Domains", str(domain_count))
    summary.add_row("Unique IPs", str(ip_count))
    summary.add_row("Services", str(service_count))
    summary.add_row("Web Endpoints", str(web_endpoint_count))
    summary.add_row("Findings", str(finding_count))
    summary.add_row("Critical", str(critical_count))
    summary.add_row("High", str(high_count))
    summary.add_row("Errors", str(len(session.errors)))


    console.print(summary)

    services = Table(title="Discovered Services")
    services.add_column("Host")
    services.add_column("Port")
    services.add_column("Service")
    services.add_column("Product")

    for result in session.scanner_results:
        for host in result.hosts:
            for service in host.services:
                services.add_row(
                    host.hostname or host.address,
                    f"{service.port}/{service.protocol}",
                    service.service or "-",
                    " ".join(
                        value
                        for value in [
                            service.product,
                            service.version,
                        ]
                        if value
                    ) or "-",
                )

    if services.row_count:
        console.print(services)

    web_endpoints = [
        asset
        for asset in session.assets
        if asset.asset_type == AssetType.WEB_ENDPOINT
    ]

    if web_endpoints:
        endpoints = Table(title="Web Endpoints")
        endpoints.add_column("URL")
        endpoints.add_column("Status", justify="right")
        endpoints.add_column("Title")
        endpoints.add_column("Technologies")

        for asset in web_endpoints:
            endpoints.add_row(
                asset.url or asset.value,
                str(asset.status_code) if asset.status_code is not None else "-",
                asset.title or "-",
                ", ".join(asset.technologies) if asset.technologies else "-",
            )

        console.print(endpoints)

    if session.wordpress_findings:
        wordpress = Table(title="WordPress Findings")
        wordpress.add_column("URL")
        wordpress.add_column("Version")
        wordpress.add_column("Plugins")
        wordpress.add_column("Themes")
        wordpress.add_column("Vulnerabilities")

        for finding in session.wordpress_findings:
            wordpress.add_row(
                finding.url,
                finding.version or "-",
                ", ".join(finding.plugins) if finding.plugins else "-",
                ", ".join(finding.themes) if finding.themes else "-",
                str(len(finding.vulnerabilities)),
            )

        console.print(wordpress)

    vulnerability_rows = [
        (finding.url, vulnerability)
        for finding in session.wordpress_findings
        for vulnerability in finding.vulnerabilities
    ]

    if vulnerability_rows:
        vulnerabilities = Table(title="WordPress Vulnerabilities")
        vulnerabilities.add_column("URL")
        vulnerabilities.add_column("Title")
        vulnerabilities.add_column("Fixed In")
        vulnerabilities.add_column("References")

        for url, vulnerability in vulnerability_rows:
            vulnerabilities.add_row(
                url,
                vulnerability.title,
                vulnerability.fixed_in or "-",
                ", ".join(vulnerability.references)
                if vulnerability.references
                else "-",
            )

        console.print(vulnerabilities)

    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
        "unknown": 5,
    }

    if session.security_findings:
        findings = Table(title="Security Findings")
        findings.add_column("Severity")
        findings.add_column("Finding")
        findings.add_column("Asset")
        findings.add_column("Scanner")
        findings.add_column("Template")

        for finding in sorted(
            session.security_findings,
            key=lambda item: severity_order.get(
                item.severity.lower(),
                5,
            ),
        ):

            findings.add_row(
                finding.severity.upper(),
                finding.title,
                finding.affected_asset,
                ", ".join(finding.discovered_by),
                finding.template_id or "-",
            )

        console.print(findings)

    if session.errors:
        errors = Table(title="Errors")
        errors.add_column("Stage")
        errors.add_column("Target")
        errors.add_column("Message")

        for error in session.errors:
            errors.add_row(
                error.stage,
                error.target,
                error.message,
            )

        console.print(errors)