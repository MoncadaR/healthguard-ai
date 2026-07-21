from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class RiskResult:
    score: int
    level: str
    findings: list[str]
    recommendations: list[str]
    positive_controls: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Convert the risk result into a regular dictionary."""

        return asdict(self)


def as_bool(value: Any) -> bool:
    """Convert form values to Boolean values."""

    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        return value == 1

    return str(value).lower() in {"true", "1", "yes", "on"}


def calculate_risk(data: dict[str, Any]) -> RiskResult:
    """
    Calculate an educational medical-device cybersecurity risk score.

    This is not a formal HIPAA, FDA, regulatory, or clinical
    risk-assessment methodology.
    """

    score = 0
    findings = []
    recommendations = []
    positive_controls = []

    support_status = data.get("support_status", "unknown")

    if support_status == "unsupported":
        score += 16
        findings.append(
            "The device uses an unsupported operating system or software."
        )
        recommendations.append(
            "Obtain a supported upgrade or document compensating controls."
        )

    elif support_status == "unknown":
        score += 8
        findings.append(
            "The support status of the operating system is unknown."
        )
        recommendations.append(
            "Confirm software lifecycle and support status with the manufacturer."
        )

    else:
        positive_controls.append(
            "The operating system or software is vendor supported."
        )

    if as_bool(data.get("end_of_life")):
        score += 16
        findings.append(
            "The medical device is identified as end of life."
        )
        recommendations.append(
            "Create a device replacement plan and apply additional access restrictions."
        )

    if as_bool(data.get("internet_access")):
        score += 14
        findings.append(
            "The device has direct or indirect internet access."
        )
        recommendations.append(
            "Remove unnecessary internet access and restrict communications."
        )

    if as_bool(data.get("vendor_remote_access")):
        score += 8
        findings.append(
            "Vendor remote access is enabled."
        )
        recommendations.append(
            "Restrict vendor access to approved accounts, times, and sources."
        )

        if not as_bool(data.get("remote_access_mfa")):
            score += 7
            findings.append(
                "Vendor remote access is not protected by multifactor authentication."
            )
            recommendations.append(
                "Require multifactor authentication for remote access."
            )
        else:
            positive_controls.append(
                "Vendor remote access uses multifactor authentication."
            )

    if as_bool(data.get("stores_phi")):
        score += 8
        findings.append(
            "The device stores or processes patient-identifiable information."
        )

        if not as_bool(data.get("encryption_at_rest")):
            score += 7
            findings.append(
                "Stored patient information is not confirmed to be encrypted."
            )
            recommendations.append(
                "Enable encryption at rest or apply an approved compensating control."
            )
        else:
            positive_controls.append(
                "Stored information is encrypted."
            )

    if as_bool(data.get("network_connected")):
        if not as_bool(data.get("network_segmented")):
            score += 11
            findings.append(
                "The network-connected device is not isolated in a dedicated segment."
            )
            recommendations.append(
                "Place the device in a dedicated medical-device VLAN."
            )
        else:
            positive_controls.append(
                "The device is placed in a dedicated network segment."
            )

        if not as_bool(data.get("encryption_transit")):
            score += 8
            findings.append(
                "Network communications are not confirmed to be encrypted."
            )
            recommendations.append(
                "Use secure and encrypted communication protocols where supported."
            )
        else:
            positive_controls.append(
                "Network communications are encrypted."
            )

    if as_bool(data.get("wireless_enabled")):
        score += 4
        findings.append(
            "Wireless connectivity increases the device attack surface."
        )
        recommendations.append(
            "Use enterprise wireless security and disable unused wireless interfaces."
        )

    if not as_bool(data.get("unique_accounts")):
        score += 7
        findings.append(
            "The device does not use unique user accounts."
        )
        recommendations.append(
            "Replace shared accounts with individually assigned accounts."
        )
    else:
        positive_controls.append(
            "The device supports unique user accounts."
        )

    if not as_bool(data.get("default_password_changed")):
        score += 12
        findings.append(
            "Default credentials may still be active."
        )
        recommendations.append(
            "Change all default credentials and disable unused default accounts."
        )
    else:
        score -= 3
        positive_controls.append(
            "Default credentials have been changed."
        )

    if not as_bool(data.get("audit_logging")):
        score += 7
        findings.append(
            "Security audit logging is unavailable or disabled."
        )
        recommendations.append(
            "Enable logging and forward security events to a protected system."
        )
    else:
        positive_controls.append(
            "Security audit logging is enabled."
        )

    if not as_bool(data.get("patch_process")):
        score += 10
        findings.append(
            "No formal security patch process was identified."
        )
        recommendations.append(
            "Create a vendor-coordinated patch and vulnerability-management process."
        )
    else:
        positive_controls.append(
            "A documented security patch process exists."
        )

    if not as_bool(data.get("antivirus_supported")):
        score += 3
        findings.append(
            "Endpoint protection is not supported or available."
        )
        recommendations.append(
            "Use network monitoring and other compensating security controls."
        )
    else:
        positive_controls.append(
            "Endpoint protection is supported."
        )

    if not as_bool(data.get("backups_available")):
        score += 5
        findings.append(
            "No backup or recovery process was identified."
        )
        recommendations.append(
            "Document backup, recovery, and clinical downtime procedures."
        )
    else:
        positive_controls.append(
            "Backup or recovery procedures are available."
        )

    score = max(0, min(score, 100))

    if score >= 75:
        level = "Critical"
    elif score >= 50:
        level = "High"
    elif score >= 25:
        level = "Medium"
    else:
        level = "Low"

    findings = list(dict.fromkeys(findings))
    recommendations = list(dict.fromkeys(recommendations))
    positive_controls = list(dict.fromkeys(positive_controls))

    return RiskResult(
        score=score,
        level=level,
        findings=findings,
        recommendations=recommendations,
        positive_controls=positive_controls,
    )