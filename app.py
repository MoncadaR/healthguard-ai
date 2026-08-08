import json
import os
from pathlib import Path

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from ai_service import generate_ai_analysis
from database import get_db, init_app, init_db
from kev_service import (
    KEVServiceError,
    fetch_kev_catalog,
    match_cves_to_kev,
)
from nvd_service import NVDServiceError, search_cves
from risk_engine import calculate_risk


load_dotenv()

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv(
    "FLASK_SECRET_KEY",
    "development-secret",
)

app.config["DATABASE"] = str(
    Path(app.instance_path) / "healthguard.db"
)

Path(app.instance_path).mkdir(
    parents=True,
    exist_ok=True,
)

init_app(app)


BOOLEAN_FIELDS = [
    "network_connected",
    "internet_access",
    "wireless_enabled",
    "stores_phi",
    "encryption_transit",
    "encryption_at_rest",
    "unique_accounts",
    "default_password_changed",
    "audit_logging",
    "network_segmented",
    "vendor_remote_access",
    "remote_access_mfa",
    "patch_process",
    "antivirus_supported",
    "backups_available",
    "end_of_life",
]


def checkbox_value(field_name: str) -> int:
    """Return 1 if the checkbox was selected and 0 otherwise."""

    return 1 if request.form.get(field_name) == "on" else 0


def clean_text(
    field_name: str,
    maximum_length: int = 200,
) -> str:
    """Read, trim, and length-limit a text form value."""

    value = request.form.get(
        field_name,
        "",
    ).strip()

    return value[:maximum_length]


def serialize_list(items: list[str]) -> str:
    """Convert a Python list into JSON text for SQLite."""

    return json.dumps(items)


def deserialize_list(value: str | None) -> list[str]:
    """Convert JSON text from SQLite back into a Python list."""

    if not value:
        return []

    try:
        result = json.loads(value)

        if isinstance(result, list):
            return result

    except json.JSONDecodeError:
        pass

    return []


def deserialize_json_list(
    value: str | None,
) -> list[dict]:
    """Convert stored JSON text into a list of dictionaries."""

    if not value:
        return []

    try:
        result = json.loads(value)

        if isinstance(result, list):
            return [
                item
                for item in result
                if isinstance(item, dict)
            ]

    except json.JSONDecodeError:
        pass

    return []


def get_assessment_or_404(
    assessment_id: int,
):
    """Retrieve one assessment or return a 404 page."""

    assessment_record = get_db().execute(
        """
        SELECT *
        FROM assessments
        WHERE id = ?
        """,
        (assessment_id,),
    ).fetchone()

    if assessment_record is None:
        abort(404)

    return assessment_record


@app.route("/")
def index():
    """Display dashboard statistics and recent assessments."""

    db = get_db()

    summary = db.execute(
        """
        SELECT
            COUNT(*) AS total,

            SUM(
                CASE
                    WHEN risk_level = 'Critical'
                    THEN 1
                    ELSE 0
                END
            ) AS critical,

            SUM(
                CASE
                    WHEN risk_level = 'High'
                    THEN 1
                    ELSE 0
                END
            ) AS high,

            ROUND(
                AVG(risk_score),
                1
            ) AS average_score

        FROM assessments
        """
    ).fetchone()

    recent = db.execute(
        """
        SELECT
            id,
            device_name,
            manufacturer,
            risk_score,
            risk_level,
            created_at

        FROM assessments

        ORDER BY created_at DESC

        LIMIT 5
        """
    ).fetchall()

    return render_template(
        "index.html",
        summary=summary,
        recent=recent,
    )


@app.route(
    "/assessment",
    methods=["GET", "POST"],
)
def assessment():
    """Display and process the device assessment form."""

    if request.method == "GET":
        return render_template(
            "assessment.html"
        )

    device_data = {
        "device_name": clean_text(
            "device_name"
        ),
        "manufacturer": clean_text(
            "manufacturer"
        ),
        "model": clean_text(
            "model"
        ),
        "device_type": clean_text(
            "device_type"
        ),
        "department": clean_text(
            "department"
        ),
        "operating_system": clean_text(
            "operating_system"
        ),
        "support_status": clean_text(
            "support_status"
        ),
        "cve_search_term": clean_text(
            "cve_search_term",
            maximum_length=150,
        ),
    }

    for field in BOOLEAN_FIELDS:
        device_data[field] = checkbox_value(
            field
        )

    if not device_data["device_name"]:
        return render_template(
            "assessment.html",
            error="Device name is required.",
            form_data=request.form,
        )

    if not device_data["device_type"]:
        return render_template(
            "assessment.html",
            error="Device type is required.",
            form_data=request.form,
        )

    if device_data["support_status"] not in {
        "supported",
        "unsupported",
        "unknown",
    }:
        return render_template(
            "assessment.html",
            error=(
                "A valid software support status "
                "is required."
            ),
            form_data=request.form,
        )

    result = calculate_risk(
        device_data
    )

    cve_records = []
    cve_results = []

    cve_lookup_error = None
    kev_lookup_error = None

    if device_data["cve_search_term"]:
        try:
            cve_records = search_cves(
                device_data[
                    "cve_search_term"
                ]
            )

            cve_results = [
                record.to_dict()
                for record in cve_records
            ]

        except NVDServiceError as exception:
            app.logger.warning(
                "NVD lookup failed: %s",
                exception,
            )

            cve_lookup_error = str(
                exception
            )

    if cve_results:
        try:
            kev_catalog = fetch_kev_catalog()

            cve_ids = [
                item["cve_id"]
                for item in cve_results
                if item.get("cve_id")
            ]

            kev_matches = match_cves_to_kev(
                cve_ids,
                kev_catalog,
            )

            for cve in cve_results:
                cve_id = cve.get(
                    "cve_id",
                    "",
                ).strip().upper()

                kev_record = kev_matches.get(
                    cve_id
                )

                if kev_record:
                    cve["known_exploited"] = True
                    cve["kev"] = kev_record.to_dict()

                else:
                    cve["known_exploited"] = False
                    cve["kev"] = None

        except KEVServiceError as exception:
            app.logger.warning(
                "CISA KEV lookup failed: %s",
                exception,
            )

            kev_lookup_error = str(
                exception
            )

            for cve in cve_results:
                cve["known_exploited"] = None
                cve["kev"] = None

    ai_analysis = None
    ai_error = None

    try:
        if app.config.get(
            "TESTING"
        ):
            ai_analysis = (
                "AI analysis disabled during "
                "automated application testing."
            )

        else:
            ai_analysis = generate_ai_analysis(
                device_data,
                result.to_dict(),
            )

    except Exception as exception:
        app.logger.exception(
            "The AI analysis could not "
            "be generated."
        )

        ai_error = str(
            exception
        )

    db = get_db()

    cursor = db.execute(
        """
        INSERT INTO assessments (
            device_name,
            manufacturer,
            model,
            device_type,
            department,
            operating_system,
            support_status,

            cve_search_term,
            cve_results,
            cve_lookup_error,
            kev_lookup_error,

            network_connected,
            internet_access,
            wireless_enabled,

            stores_phi,
            encryption_transit,
            encryption_at_rest,

            unique_accounts,
            default_password_changed,
            audit_logging,

            network_segmented,
            vendor_remote_access,
            remote_access_mfa,

            patch_process,
            antivirus_supported,
            backups_available,
            end_of_life,

            risk_score,
            risk_level,

            findings,
            recommendations,
            positive_controls,
            ai_analysis
        )

        VALUES (
            ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?,
            ?, ?, ?, ?
        )
        """,
        (
            device_data["device_name"],
            device_data["manufacturer"],
            device_data["model"],
            device_data["device_type"],
            device_data["department"],
            device_data["operating_system"],
            device_data["support_status"],

            device_data["cve_search_term"],
            json.dumps(cve_results),
            cve_lookup_error,
            kev_lookup_error,

            device_data["network_connected"],
            device_data["internet_access"],
            device_data["wireless_enabled"],

            device_data["stores_phi"],
            device_data["encryption_transit"],
            device_data["encryption_at_rest"],

            device_data["unique_accounts"],
            device_data["default_password_changed"],
            device_data["audit_logging"],

            device_data["network_segmented"],
            device_data["vendor_remote_access"],
            device_data["remote_access_mfa"],

            device_data["patch_process"],
            device_data["antivirus_supported"],
            device_data["backups_available"],
            device_data["end_of_life"],

            result.score,
            result.level,

            serialize_list(
                result.findings
            ),
            serialize_list(
                result.recommendations
            ),
            serialize_list(
                result.positive_controls
            ),
            ai_analysis,
        ),
    )

    db.commit()

    assessment_id = cursor.lastrowid

    if ai_error:
        flash(
            "The rule-based assessment was "
            "completed, but the AI analysis "
            "was unavailable.",
            "warning",
        )

    return redirect(
        url_for(
            "view_result",
            assessment_id=assessment_id,
        )
    )


@app.route(
    "/result/<int:assessment_id>"
)
def view_result(
    assessment_id: int,
):
    """Display one saved assessment."""

    assessment_record = get_assessment_or_404(
        assessment_id
    )

    return render_template(
        "result.html",
        assessment=assessment_record,
        findings=deserialize_list(
            assessment_record["findings"]
        ),
        recommendations=deserialize_list(
            assessment_record["recommendations"]
        ),
        positive_controls=deserialize_list(
            assessment_record["positive_controls"]
        ),
        cve_results=deserialize_json_list(
            assessment_record["cve_results"]
        ),
    )


@app.route("/history")
def history():
    """Display all saved assessments."""

    assessments = get_db().execute(
        """
        SELECT
            id,
            device_name,
            manufacturer,
            model,
            device_type,
            risk_score,
            risk_level,
            created_at

        FROM assessments

        ORDER BY created_at DESC
        """
    ).fetchall()

    return render_template(
        "history.html",
        assessments=assessments,
    )


@app.route(
    "/report/<int:assessment_id>"
)
def report(
    assessment_id: int,
):
    """Display a printable assessment report."""

    assessment_record = get_assessment_or_404(
        assessment_id
    )

    return render_template(
        "report.html",
        assessment=assessment_record,
        findings=deserialize_list(
            assessment_record["findings"]
        ),
        recommendations=deserialize_list(
            assessment_record["recommendations"]
        ),
        positive_controls=deserialize_list(
            assessment_record["positive_controls"]
        ),
        cve_results=deserialize_json_list(
            assessment_record["cve_results"]
        ),
    )


@app.errorhandler(404)
def not_found(error):
    """Display a friendly 404 page."""

    return render_template(
        "error.html",
        title="Assessment Not Found",
        message=(
            "The requested assessment "
            "could not be found."
        ),
    ), 404


@app.errorhandler(500)
def internal_error(error):
    """Display a friendly application error page."""

    return render_template(
        "error.html",
        title="Application Error",
        message=(
            "The application encountered an "
            "unexpected error. Review the "
            "Terminal logs for additional "
            "information."
        ),
    ), 500


@app.cli.command("init-db")
def init_db_command():
    """Create or reset the SQLite database."""

    init_db()

    print(
        "Database initialized successfully."
    )


if __name__ == "__main__":
    app.run(
        debug=True,
        port=5001,
    )