import os
import tempfile

import pytest

from app import app
from database import init_db


@pytest.fixture
def client():
    """Create an isolated Flask test client."""

    database_file = tempfile.NamedTemporaryFile(
        suffix=".db",
        delete=False,
    )

    database_file.close()

    app.config.update(
        {
            "TESTING": True,
            "DATABASE": database_file.name,
            "SECRET_KEY": "testing-secret",
        }
    )

    with app.app_context():
        init_db()

    with app.test_client() as test_client:
        yield test_client

    os.unlink(database_file.name)


def test_home_page_loads(client):
    response = client.get("/")

    assert response.status_code == 200
    assert b"HealthGuard AI" in response.data


def test_assessment_page_loads(client):
    response = client.get("/assessment")

    assert response.status_code == 200
    assert b"New Medical-Device Assessment" in response.data


def test_missing_device_name_is_rejected(client):
    response = client.post(
        "/assessment",
        data={
            "device_name": "",
            "device_type": "Patient Monitor",
            "support_status": "supported",
        },
    )

    assert response.status_code == 200
    assert b"Device name is required" in response.data


def test_missing_device_type_is_rejected(client):
    response = client.post(
        "/assessment",
        data={
            "device_name": "Test Device",
            "device_type": "",
            "support_status": "supported",
        },
    )

    assert response.status_code == 200
    assert b"Device type is required" in response.data


def test_history_page_loads(client):
    response = client.get("/history")

    assert response.status_code == 200
    assert b"Assessment History" in response.data


def test_invalid_assessment_returns_404(client):
    response = client.get("/result/99999")

    assert response.status_code == 404

def test_valid_assessment_is_saved(client):
    response = client.post(
        "/assessment",
        data={
            "device_name": "Test Patient Monitor",
            "device_type": "Patient Monitor",
            "manufacturer": "Training Manufacturer",
            "model": "PM-100",
            "department": "ICU",
            "operating_system": "Embedded Linux",
            "support_status": "supported",
            "network_connected": "on",
            "encryption_transit": "on",
            "unique_accounts": "on",
            "default_password_changed": "on",
            "audit_logging": "on",
            "network_segmented": "on",
            "patch_process": "on",
            "antivirus_supported": "on",
            "backups_available": "on",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Test Patient Monitor" in response.data
    assert b"AI-Assisted Security Analysis" in response.data