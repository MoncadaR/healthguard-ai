from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class MitreTechnique:
    technique_id: str
    name: str
    tactic: str
    reason: str
    source_url: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


MITRE_TECHNIQUES = {
    "default_credentials": MitreTechnique(
        technique_id="T1078.001",
        name="Default Accounts",
        tactic="Initial Access / Persistence / Privilege Escalation",
        reason=(
            "Default or unchanged credentials may allow an adversary "
            "to authenticate using legitimate accounts."
        ),
        source_url=(
            "https://attack.mitre.org/techniques/T1078/001/"
        ),
    ),

    "weak_account_controls": MitreTechnique(
        technique_id="T1078",
        name="Valid Accounts",
        tactic="Initial Access / Persistence / Privilege Escalation",
        reason=(
            "Weak account controls may increase the possibility that "
            "valid credentials could be abused."
        ),
        source_url=(
            "https://attack.mitre.org/techniques/T1078/"
        ),
    ),

    "vendor_remote_access": MitreTechnique(
        technique_id="T1133",
        name="External Remote Services",
        tactic="Initial Access / Persistence",
        reason=(
            "Externally accessible vendor remote services can provide "
            "a pathway into internal systems if compromised or misused."
        ),
        source_url=(
            "https://attack.mitre.org/techniques/T1133/"
        ),
    ),

    "remote_services": MitreTechnique(
        technique_id="T1021",
        name="Remote Services",
        tactic="Lateral Movement",
        reason=(
            "Remote administration services may be abused to access "
            "systems or move between systems when credentials are available."
        ),
        source_url=(
            "https://attack.mitre.org/techniques/T1021/"
        ),
    ),

    "internet_exposure": MitreTechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
        reason=(
            "Internet-accessible services may expose exploitable software "
            "or management interfaces to external adversaries."
        ),
        source_url=(
            "https://attack.mitre.org/techniques/T1190/"
        ),
    ),
}


def map_assessment_to_mitre(
    device_data: dict[str, Any],
) -> list[MitreTechnique]:
    """
    Map assessment conditions to potentially relevant MITRE ATT&CK techniques.

    These mappings describe plausible adversary techniques associated with
    identified exposure conditions. They do not indicate observed attacks.
    """

    techniques: list[MitreTechnique] = []

    if not bool(
        device_data.get("default_password_changed")
    ):
        techniques.append(
            MITRE_TECHNIQUES["default_credentials"]
        )

    if not bool(
        device_data.get("unique_accounts")
    ):
        techniques.append(
            MITRE_TECHNIQUES["weak_account_controls"]
        )

    if bool(
        device_data.get("vendor_remote_access")
    ):
        techniques.append(
            MITRE_TECHNIQUES["vendor_remote_access"]
        )

        techniques.append(
            MITRE_TECHNIQUES["remote_services"]
        )

    if bool(
        device_data.get("internet_access")
    ):
        techniques.append(
            MITRE_TECHNIQUES["internet_exposure"]
        )

    unique_techniques: dict[str, MitreTechnique] = {}

    for technique in techniques:
        unique_techniques[
            technique.technique_id
        ] = technique

    return list(
        unique_techniques.values()
    )