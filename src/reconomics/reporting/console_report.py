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

    summary = Table(title="Scan Summary")
    summary.add_column("Metric")
    summary.add_column("Count", justify="right")

    summary.add_row("Domains", str(domain_count))
    summary.add_row("Unique IPs", str(ip_count))
    summary.add_row("Services", str(service_count))
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