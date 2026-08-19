import logging
from datetime import datetime, timezone

from reconomics.models import (
    Asset,
    AssetRelationship,
    AssetType,
    RelationshipType,
    ScanError,
    ScanSession,
)
from reconomics.resolver import resolve_domain
from reconomics.scanners.httpx import HttpxScanner
from reconomics.scanners.nmap import NmapScanner
from reconomics.scanners.nuclei import NucleiScanner
from reconomics.scanners.subfinder import SubfinderScanner
from reconomics.scanners.wpscan import WPScanScanner
from reconomics.targets import TargetType, classify_target
from reconomics.technology import has_technology
from reconomics.web import is_web_service

logger = logging.getLogger(__name__)

class ScanOrchestrator:
    def __init__(self) -> None:
        self.scanners = [
            NmapScanner(),
            SubfinderScanner(),
        ]

    def _add_nmap_assets(
        self,
        session: ScanSession,
        result,
    ) -> None:
        existing_assets = {
            (asset.asset_type, asset.value)
            for asset in session.assets
        }

        existing_relationships = {
            (
                relationship.source,
                relationship.target,
                relationship.relationship_type,
            )
            for relationship in session.relationships
        }

        for host in result.hosts:
            host_key = (
                AssetType.IP,
                host.address,
            )

            if host_key not in existing_assets:
                session.assets.append(
                    Asset(
                        value=host.address,
                        asset_type=AssetType.IP,
                        discovered_by="nmap",
                    )
                )

                existing_assets.add(host_key)

            for service in host.services:
                service_id = (
                    f"{host.address}:{service.protocol}:{service.port}"
                )

                asset_key = (
                    AssetType.SERVICE,
                    service_id,
                )

                if asset_key not in existing_assets:
                    session.assets.append(
                        Asset(
                            value=service_id,
                            asset_type=AssetType.SERVICE,
                            discovered_by="nmap",
                            port=service.port,
                            protocol=service.protocol,
                            service=service.service,
                            product=service.product,
                            version=service.version,
                        )
                    )

                    existing_assets.add(asset_key)

                relationship_key = (
                    host.address,
                    service_id,
                    RelationshipType.EXPOSES,
                )

                if relationship_key not in existing_relationships:
                    session.relationships.append(
                        AssetRelationship(
                            source=host.address,
                            target=service_id,
                            relationship_type=RelationshipType.EXPOSES,
                            discovered_by="nmap",
                        )
                    )

                    existing_relationships.add(
                        relationship_key
                    )

    def _service_to_url(self, asset: Asset) -> str | None:
        if not is_web_service(asset):
            return None

        if asset.port is None:
            return None

        host = asset.value.split(":tcp:")[0]

        if asset.service == "https" or asset.port in {443, 8443}:
            scheme = "https"
        else:
            scheme = "http"

        default_port = (
            scheme == "http" and asset.port == 80
        ) or (
            scheme == "https" and asset.port == 443
        )

        if default_port:
            return f"{scheme}://{host}"

        return f"{scheme}://{host}:{asset.port}"
    
    def _domains_for_ip(
        self,
        session: ScanSession,
        ip_address: str,
    ) -> list[str]:
        domains = []

        for relationship in session.relationships:
            if (
                relationship.relationship_type
                == RelationshipType.RESOLVES_TO
                and relationship.target == ip_address
            ):
                domains.append(relationship.source)

        return sorted(set(domains))
    
    def _service_to_hostname_url(
        self,
        service_asset: Asset,
        hostname: str,
    ) -> str | None:
        if not is_web_service(service_asset):
            return None

        if service_asset.port is None:
            return None

        if (
            service_asset.service == "https"
            or service_asset.port in {443, 8443}
        ):
            scheme = "https"
        else:
            scheme = "http"

        default_port = (
            scheme == "http"
            and service_asset.port == 80
        ) or (
            scheme == "https"
            and service_asset.port == 443
        )

        if default_port:
            return f"{scheme}://{hostname}"

        return f"{scheme}://{hostname}:{service_asset.port}"

    def run(self, target: str) -> ScanSession:
        session = ScanSession(target=target)

        target_type = classify_target(target)

        # Add the user-supplied target as the root asset in the graph

        if target_type == TargetType.DOMAIN:
            session.assets.append(
                Asset(
                    value=target,
                    asset_type=AssetType.DOMAIN,
                    discovered_by="input",
                )
            )

        elif target_type == TargetType.IP:
            session.assets.append(
                Asset(
                    value=target,
                    asset_type=AssetType.IP,
                    discovered_by="input",
                )
            )

        logger.info(
            "Classified target %s as %s",
            target,
            target_type.value,
        )


        # Phase 1: Run scanners against the original target
        for scanner in self.scanners:
            if not scanner.supports(target_type):
                continue

            logger.info(
            "Running %s against %s",
            scanner.__class__.__name__,
            target,
            )

            try:
                result = scanner.scan(target)

            except Exception as exc:
                
                #Scan Failure Log
                logger.error(
                "%s failed against %s: %s",
                scanner.__class__.__name__,
                target,
                exc,
                )

                session.errors.append(
                    ScanError(
                        stage="initial_scan",
                        scanner=scanner.__class__.__name__,
                        target=target,
                        message=str(exc),
                    )
                )
                continue

            #Scan Success Log
            logger.info(
            "%s completed successfully",
            scanner.__class__.__name__,
            )

            session.scanner_results.append(result)

            if result.scanner == "nmap":
                self._add_nmap_assets(session, result)

            if result.scanner == "subfinder":
                for domain in result.domains:
                    session.assets.append(
                        Asset(
                            value=domain.name,
                            asset_type=AssetType.DOMAIN,
                            discovered_by="subfinder",
                        )
                    )
            # Turn Subfinder discoveries into domain assets
            if result.scanner == "subfinder":
                existing_domains = {
                    asset.value
                    for asset in session.assets
                    if asset.asset_type == AssetType.DOMAIN
                }

                for domain in result.domains:
                    if domain.name in existing_domains:
                        continue

                    session.assets.append(
                        Asset(
                            value=domain.name,
                            asset_type=AssetType.DOMAIN,
                            discovered_by="subfinder",
                        )
                    )

                    existing_domains.add(domain.name)



        # Phase 2: Resolve discovered domains to IP addresses
        domain_assets = [
            asset
            for asset in session.assets
            if asset.asset_type == AssetType.DOMAIN
        ]

        logger.info(
        "Resolving %d discovered domains",
        len(domain_assets),
        )

        ip_assets: dict[str, Asset] = {}

        for domain_asset in domain_assets:
            resolved_assets = resolve_domain(
                domain_asset.value
            )

            for ip_asset in resolved_assets:
                session.relationships.append(
                    AssetRelationship(
                        source=domain_asset.value,
                        target=ip_asset.value,
                        relationship_type=RelationshipType.RESOLVES_TO,
                        discovered_by="dns",
                    )
                )

                existing = ip_assets.get(
                    ip_asset.value
                )

                if existing:
                    for domain in ip_asset.related_domains:
                        if domain not in existing.related_domains:
                            existing.related_domains.append(domain)
                else:
                    ip_assets[ip_asset.value] = ip_asset

        session.assets.extend(
            ip_assets.values()
        )

        logger.info(
        "DNS resolution produced %d unique IP assets",
        len(ip_assets),
        )

        # Phase 3: Nmap newly discovered IP assets

        nmap_scanner = NmapScanner()

        already_scanned_ips = set()

        for result in session.scanner_results:
            if result.scanner != "nmap":
                continue

            for host in result.hosts:
                already_scanned_ips.add(host.address)

        for ip_asset in ip_assets.values():
            if ip_asset.value in already_scanned_ips:
                continue

            logger.info(
            "Running Nmap against discovered IP %s",
            ip_asset.value,
            )

            if ip_asset.value in already_scanned_ips:
                logger.debug(
                "Skipping already-scanned IP %s",
                ip_asset.value,
                )
                continue

            try:
                result = nmap_scanner.scan(ip_asset.value)

            except Exception as exc:
                session.errors.append(
                    ScanError(
                        stage="discovered_asset_scan",
                        scanner="nmap",
                        target=ip_asset.value,
                        message=str(exc),
                    )
                )
                continue

            session.scanner_results.append(result)

            self._add_nmap_assets(session, result)

            already_scanned_ips.add(ip_asset.value)

        # Phase 4: Enrich discovered web services with httpx

        httpx_scanner = HttpxScanner()

        service_assets = [
            asset
            for asset in session.assets
            if asset.asset_type == AssetType.SERVICE
            and is_web_service(asset)
        ]

        logger.info(
            "Identified %d web-capable services for httpx enrichment",
            len(service_assets),
        )

        existing_assets = {
            (asset.asset_type, asset.value)
            for asset in session.assets
        }

        existing_relationships = {
            (
                relationship.source,
                relationship.target,
                relationship.relationship_type,
            )
            for relationship in session.relationships
        }

        for service_asset in service_assets:
            host_ip = service_asset.value.split(":tcp:")[0]

            domains = self._domains_for_ip(
                session,
                host_ip,
            )

            urls = []

            if domains:
                for domain in domains:
                    url = self._service_to_hostname_url(
                        service_asset,
                        domain,
                    )

                    if url:
                        urls.append(url)

            else:
                url = self._service_to_url(
                    service_asset
                )

                if url:
                    urls.append(url)

            for url in urls:
                logger.info(
                    "Running httpx against %s",
                    url,
                )

                try:
                    httpx_result = httpx_scanner.scan_url(
                        url
                    )

                except Exception as exc:
                    session.errors.append(
                        ScanError(
                            stage="web_enrichment",
                            scanner="httpx",
                            target=url,
                            message=str(exc),
                        )
                    )
                    continue

                if not httpx_result:
                    continue

                endpoint_url = (
                    httpx_result.get("url")
                    or url
                )

                endpoint_key = (
                    AssetType.WEB_ENDPOINT,
                    endpoint_url,
                )

                if endpoint_key not in existing_assets:
                    session.assets.append(
                        Asset(
                            value=endpoint_url,
                            asset_type=AssetType.WEB_ENDPOINT,
                            discovered_by="httpx",
                            url=endpoint_url,
                            status_code=httpx_result.get(
                                "status_code"
                            ),
                            title=httpx_result.get("title"),
                            technologies=httpx_result.get(
                                "tech",
                                [],
                            ),
                        )
                    )

                    existing_assets.add(
                        endpoint_key
                    )

                relationship_key = (
                    service_asset.value,
                    endpoint_url,
                    RelationshipType.SERVES,
                )

                if (
                    relationship_key
                    not in existing_relationships
                ):
                    session.relationships.append(
                        AssetRelationship(
                            source=service_asset.value,
                            target=endpoint_url,
                            relationship_type=RelationshipType.SERVES,
                            discovered_by="httpx",
                        )
                    )

                    existing_relationships.add(
                        relationship_key
                    )

        # Phase 5: Run specialist WordPress enrichment

        wpscan_scanner = WPScanScanner()

        wordpress_endpoints = [
            asset
            for asset in session.assets
            if asset.asset_type == AssetType.WEB_ENDPOINT
            and has_technology(asset, "WordPress")
        ]

        logger.info(
            "Identified %d WordPress endpoints for WPScan",
            len(wordpress_endpoints),
        )

        for endpoint in wordpress_endpoints:
            if not endpoint.url:
                continue

            logger.info(
                "Running WPScan against %s",
                endpoint.url,
            )

            try:
                finding = wpscan_scanner.scan_url(
                    endpoint.url
                )

            except Exception as exc:
                session.errors.append(
                    ScanError(
                        stage="wordpress_enrichment",
                        scanner="wpscan",
                        target=endpoint.url,
                        message=str(exc),
                    )
                )
                continue

            session.wordpress_findings.append(
                finding
            )

        # Phase 6: Run Nuclei against confirmed web endpoints

        nuclei_scanner = NucleiScanner()

        web_endpoints = [
            asset
            for asset in session.assets
            if asset.asset_type == AssetType.WEB_ENDPOINT
            and asset.url
        ]

        logger.info(
            "Identified %d web endpoints for Nuclei",
            len(web_endpoints),
        )

        for endpoint in web_endpoints:
            logger.info(
                "Running Nuclei against %s",
                endpoint.url,
            )

            try:
                findings = nuclei_scanner.scan_url(
                    endpoint.url,
                )

            except Exception as exc:
                session.errors.append(
                    ScanError(
                        stage="vulnerability_scanning",
                        scanner="nuclei",
                        target=endpoint.url,
                        message=str(exc),
                    )
                )
                continue

            session.security_findings.extend(
                findings
            )

            logger.info(
                "Nuclei found %d findings against %s",
                len(findings),
                endpoint.url,
            )

        # All current phases are finished
        session.completed_at = datetime.now(
            timezone.utc
        )

        return session