from mitre_service import map_assessment_to_mitre


def technique_ids(device_data: dict) -> set[str]:
    return {
        item.technique_id
        for item in map_assessment_to_mitre(
            device_data
        )
    }


def test_default_credentials_map_to_default_accounts():
    data = {
        "default_password_changed": False,
        "unique_accounts": True,
        "vendor_remote_access": False,
        "internet_access": False,
    }

    assert "T1078.001" in technique_ids(data)


def test_vendor_remote_access_maps_to_remote_techniques():
    data = {
        "default_password_changed": True,
        "unique_accounts": True,
        "vendor_remote_access": True,
        "internet_access": False,
    }

    ids = technique_ids(data)

    assert "T1133" in ids
    assert "T1021" in ids


def test_internet_access_maps_to_t1190():
    data = {
        "default_password_changed": True,
        "unique_accounts": True,
        "vendor_remote_access": False,
        "internet_access": True,
    }

    assert "T1190" in technique_ids(data)


def test_secure_device_has_no_mappings():
    data = {
        "default_password_changed": True,
        "unique_accounts": True,
        "vendor_remote_access": False,
        "internet_access": False,
    }

    assert map_assessment_to_mitre(data) == []