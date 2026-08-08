from dataclasses import asdict, dataclass
from typing import Any

import requests


CISA_KEV_JSON_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


@dataclass
class KEVRecord:
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str
    known_ransomware_use: str
    notes: str
    cwes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class KEVServiceError(RuntimeError):
    """Raised when the CISA KEV feed cannot be retrieved."""


def fetch_kev_catalog() -> dict[str, KEVRecord]:
    """
    Download the CISA KEV catalog.

    Returns a dictionary indexed by CVE ID:

    {
        "CVE-2021-44228": KEVRecord(...),
        ...
    }
    """

    headers = {
        "User-Agent": (
            "HealthGuard-AI/1.0 "
            "(educational cybersecurity research project)"
        )
    }

    try:
        response = requests.get(
            CISA_KEV_JSON_URL,
            headers=headers,
            timeout=30,
        )

        response.raise_for_status()

    except requests.Timeout as exception:
        raise KEVServiceError(
            "The CISA KEV request timed out."
        ) from exception

    except requests.RequestException as exception:
        raise KEVServiceError(
            "The CISA KEV catalog could not be downloaded."
        ) from exception

    try:
        payload = response.json()

    except ValueError as exception:
        raise KEVServiceError(
            "The CISA KEV response was not valid JSON."
        ) from exception

    catalog: dict[str, KEVRecord] = {}

    for item in payload.get("vulnerabilities", []):
        cve_id = str(
            item.get("cveID", "")
        ).strip().upper()

        if not cve_id:
            continue

        raw_cwes = item.get("cwes", [])

        if isinstance(raw_cwes, list):
            cwes = [
                str(cwe).strip()
                for cwe in raw_cwes
                if str(cwe).strip()
            ]
        else:
            cwes = []

        catalog[cve_id] = KEVRecord(
            cve_id=cve_id,
            vendor_project=str(
                item.get("vendorProject", "")
            ).strip(),
            product=str(
                item.get("product", "")
            ).strip(),
            vulnerability_name=str(
                item.get("vulnerabilityName", "")
            ).strip(),
            date_added=str(
                item.get("dateAdded", "")
            ).strip(),
            short_description=str(
                item.get("shortDescription", "")
            ).strip(),
            required_action=str(
                item.get("requiredAction", "")
            ).strip(),
            due_date=str(
                item.get("dueDate", "")
            ).strip(),
            known_ransomware_use=str(
                item.get(
                    "knownRansomwareCampaignUse",
                    "Unknown",
                )
            ).strip(),
            notes=str(
                item.get("notes", "")
            ).strip(),
            cwes=cwes,
        )

    return catalog


def match_cves_to_kev(
    cve_ids: list[str],
    catalog: dict[str, KEVRecord],
) -> dict[str, KEVRecord]:
    """Return KEV records matching the supplied CVE IDs."""

    matches: dict[str, KEVRecord] = {}

    for cve_id in cve_ids:
        normalized_id = str(cve_id).strip().upper()

        if normalized_id in catalog:
            matches[normalized_id] = catalog[normalized_id]

    return matches