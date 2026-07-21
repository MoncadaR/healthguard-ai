import json
import os
from typing import Any

from openai import OpenAI


def get_openai_client() -> OpenAI:
    """Create an OpenAI client using the environment API key."""

    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY is missing from the .env file."
        )

    return OpenAI(api_key=api_key)


def generate_ai_analysis(
    device_data: dict[str, Any],
    risk_result: dict[str, Any],
) -> str:
    """
    Generate an AI-assisted explanation of a rule-based assessment.

    The AI explains the existing score. It does not calculate or
    replace the score produced by the local risk engine.
    """

    client = get_openai_client()

    model = os.getenv(
        "OPENAI_MODEL",
        "gpt-5-mini",
    )

    safe_device_context = {
        "device_name": device_data.get("device_name"),
        "manufacturer": device_data.get("manufacturer"),
        "model": device_data.get("model"),
        "device_type": device_data.get("device_type"),
        "department": device_data.get("department"),
        "operating_system": device_data.get("operating_system"),
        "support_status": device_data.get("support_status"),
        "network_connected": bool(
            device_data.get("network_connected")
        ),
        "internet_access": bool(
            device_data.get("internet_access")
        ),
        "wireless_enabled": bool(
            device_data.get("wireless_enabled")
        ),
        "stores_phi": bool(
            device_data.get("stores_phi")
        ),
        "vendor_remote_access": bool(
            device_data.get("vendor_remote_access")
        ),
        "remote_access_mfa": bool(
            device_data.get("remote_access_mfa")
        ),
        "end_of_life": bool(
            device_data.get("end_of_life")
        ),
    }

    prompt = f"""
You are a healthcare cybersecurity analyst supporting an
educational medical-device risk-assessment prototype.

Use only the supplied device information and application-generated
risk findings.

Do not invent:
- CVE identifiers
- Product vulnerabilities
- Product features
- Manufacturer statements
- Affected software versions
- Regulatory findings
- Legal conclusions
- Clinical facts

Do not declare the device or organization HIPAA compliant or
noncompliant.

Do not change the application-calculated score or risk level.

Do not recommend disconnecting or isolating a clinical device without
stating that biomedical engineering, clinical leadership, and patient
care continuity must first be considered.

DEVICE INFORMATION:

{json.dumps(safe_device_context, indent=2)}

APPLICATION-CALCULATED RESULT:

{json.dumps(risk_result, indent=2)}

Generate the assessment using exactly these headings:

Executive Summary

Primary Cybersecurity Risks

Patient-Safety and Operational Considerations

HIPAA Security Considerations

Immediate Priority Actions

Long-Term Recommendations

Limitations and Assumptions

Requirements:

- Explain why the application assigned the score.
- Prioritize the most important three to five actions.
- Distinguish confirmed information from missing or unknown details.
- Keep the writing professional and understandable.
- State that the output is educational decision support.
- State that it is not a compliance certification.
"""

    response = client.responses.create(
        model=model,
        input=prompt,
    )

    analysis_text = response.output_text.strip()

    if not analysis_text:
        raise RuntimeError(
            "The OpenAI API returned an empty response."
        )

    return analysis_text