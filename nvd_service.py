import os
from dataclasses import asdict, dataclass
from typing import Any

import requests


NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class CVERecord:
    cve_id: str
    description: str
    published: str | None
    last_modified: str | None
    cvss_score: float | None
    severity: str
    vector: str | None
    source_url: str
    match_status: str = "Potential keyword match"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class NVDServiceError(RuntimeError):
    """Raised when the NVD service cannot complete a request."""


def _get_english_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions", [])

    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "Description unavailable.")

    return "Description unavailable."


def _extract_cvss(cve: dict[str, Any]) -> tuple[
    float | None,
    str,
    str | None,
]:
    """
    Return the best available CVSS score, severity, and vector.

    Preference:
    1. CVSS v4.0
    2. CVSS v3.1
    3. CVSS v3.0
    4. CVSS v2.0
    """

    metrics = cve.get("metrics", {})

    metric_names = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ]

    for metric_name in metric_names:
        entries = metrics.get(metric_name, [])

        if not entries:
            continue

        metric = entries[0]
        cvss_data = metric.get("cvssData", {})

        score = cvss_data.get("baseScore")

        severity = (
            cvss_data.get("baseSeverity")
            or metric.get("baseSeverity")
            or "UNKNOWN"
        )

        vector = cvss_data.get("vectorString")

        try:
            normalized_score = float(score) if score is not None else None
        except (TypeError, ValueError):
            normalized_score = None

        return normalized_score, str(severity).upper(), vector

    return None, "UNKNOWN", None


def _build_headers() -> dict[str, str]:
    headers = {
        "User-Agent": (
            "HealthGuard-AI/1.0 "
            "(educational cybersecurity research project)"
        )
    }

    api_key = os.getenv("NVD_API_KEY", "").strip()

    if api_key:
        headers["apiKey"] = api_key

    return headers


def search_cves(
    keyword: str,
    results_limit: int | None = None,
) -> list[CVERecord]:
    """
    Search NVD CVE descriptions using a keyword or phrase.

    Results are potential matches only. A keyword match does not
    establish that the assessed device or version is vulnerable.
    """

    normalized_keyword = " ".join(keyword.split()).strip()

    if len(normalized_keyword) < 3:
        return []

    if results_limit is None:
        try:
            results_limit = int(
                os.getenv("NVD_RESULTS_LIMIT", "10")
            )
        except ValueError:
            results_limit = 10

    results_limit = max(1, min(results_limit, 20))

    params = {
        "keywordSearch": normalized_keyword,
        "resultsPerPage": results_limit,
    }

    try:
        response = requests.get(
            NVD_CVE_API_URL,
            params=params,
            headers=_build_headers(),
            timeout=20,
        )

        response.raise_for_status()

    except requests.Timeout as exception:
        raise NVDServiceError(
            "The NVD request timed out."
        ) from exception

    except requests.RequestException as exception:
        message = "The NVD request failed."

        if getattr(exception, "response", None) is not None:
            nvd_message = exception.response.headers.get("message")

            if nvd_message:
                message = f"{message} NVD message: {nvd_message}"

        raise NVDServiceError(message) from exception

    payload = response.json()
    records: list[CVERecord] = []

    for vulnerability in payload.get("vulnerabilities", []):
        cve = vulnerability.get("cve", {})
        cve_id = cve.get("id")

        if not cve_id:
            continue

        score, severity, vector = _extract_cvss(cve)

        records.append(
            CVERecord(
                cve_id=cve_id,
                description=_get_english_description(cve),
                published=cve.get("published"),
                last_modified=cve.get("lastModified"),
                cvss_score=score,
                severity=severity,
                vector=vector,
                source_url=(
                    f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                ),
            )
        )

    records.sort(
        key=lambda record: record.published or "",
        reverse=True,
    )

    return records