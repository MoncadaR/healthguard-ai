from risk_engine import calculate_risk


def secure_device() -> dict:
    """Return a sample device with strong security controls."""

    return {
        "support_status": "supported",
        "end_of_life": False,
        "internet_access": False,
        "vendor_remote_access": False,
        "remote_access_mfa": False,
        "stores_phi": False,
        "encryption_at_rest": True,
        "network_connected": True,
        "network_segmented": True,
        "encryption_transit": True,
        "wireless_enabled": False,
        "unique_accounts": True,
        "default_password_changed": True,
        "audit_logging": True,
        "patch_process": True,
        "antivirus_supported": True,
        "backups_available": True,
    }


def test_secure_device_is_low_risk():
    result = calculate_risk(secure_device())

    assert result.level == "Low"
    assert 0 <= result.score <= 24


def test_unsupported_operating_system_adds_finding():
    data = secure_device()
    data["support_status"] = "unsupported"

    result = calculate_risk(data)

    assert any(
        "unsupported operating system" in finding.lower()
        for finding in result.findings
    )


def test_internet_access_increases_score():
    baseline = calculate_risk(secure_device())

    exposed_device = secure_device()
    exposed_device["internet_access"] = True

    exposed_result = calculate_risk(exposed_device)

    assert exposed_result.score > baseline.score


def test_remote_access_without_mfa_creates_warning():
    data = secure_device()
    data["vendor_remote_access"] = True
    data["remote_access_mfa"] = False

    result = calculate_risk(data)

    assert any(
        "multifactor authentication" in finding.lower()
        for finding in result.findings
    )


def test_phi_without_encryption_creates_warning():
    data = secure_device()
    data["stores_phi"] = True
    data["encryption_at_rest"] = False

    result = calculate_risk(data)

    assert any(
        "not confirmed to be encrypted" in finding.lower()
        for finding in result.findings
    )


def test_legacy_exposed_device_is_high_or_critical():
    data = secure_device()

    data.update(
        {
            "support_status": "unsupported",
            "end_of_life": True,
            "internet_access": True,
            "vendor_remote_access": True,
            "remote_access_mfa": False,
            "stores_phi": True,
            "encryption_at_rest": False,
            "network_segmented": False,
            "encryption_transit": False,
            "unique_accounts": False,
            "default_password_changed": False,
            "audit_logging": False,
            "patch_process": False,
            "antivirus_supported": False,
            "backups_available": False,
        }
    )

    result = calculate_risk(data)

    assert result.level in {"High", "Critical"}
    assert result.score >= 50


def test_score_never_exceeds_one_hundred():
    data = {
        "support_status": "unsupported",
        "end_of_life": True,
        "internet_access": True,
        "vendor_remote_access": True,
        "remote_access_mfa": False,
        "stores_phi": True,
        "encryption_at_rest": False,
        "network_connected": True,
        "network_segmented": False,
        "encryption_transit": False,
        "wireless_enabled": True,
        "unique_accounts": False,
        "default_password_changed": False,
        "audit_logging": False,
        "patch_process": False,
        "antivirus_supported": False,
        "backups_available": False,
    }

    result = calculate_risk(data)

    assert result.score == 100


def test_score_never_goes_below_zero():
    data = secure_device()

    result = calculate_risk(data)

    assert result.score >= 0