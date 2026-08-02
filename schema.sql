DROP TABLE IF EXISTS assessments;

CREATE TABLE assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    device_name TEXT NOT NULL,
    manufacturer TEXT,
    model TEXT,
    device_type TEXT NOT NULL,
    department TEXT,
    operating_system TEXT,
    support_status TEXT NOT NULL,
    cve_search_term TEXT,
    cve_results TEXT NOT NULL DEFAULT '[]',
    cve_lookup_error TEXT,

    network_connected INTEGER NOT NULL DEFAULT 0,
    internet_access INTEGER NOT NULL DEFAULT 0,
    wireless_enabled INTEGER NOT NULL DEFAULT 0,

    stores_phi INTEGER NOT NULL DEFAULT 0,
    encryption_transit INTEGER NOT NULL DEFAULT 0,
    encryption_at_rest INTEGER NOT NULL DEFAULT 0,

    unique_accounts INTEGER NOT NULL DEFAULT 0,
    default_password_changed INTEGER NOT NULL DEFAULT 0,
    audit_logging INTEGER NOT NULL DEFAULT 0,

    network_segmented INTEGER NOT NULL DEFAULT 0,
    vendor_remote_access INTEGER NOT NULL DEFAULT 0,
    remote_access_mfa INTEGER NOT NULL DEFAULT 0,

    patch_process INTEGER NOT NULL DEFAULT 0,
    antivirus_supported INTEGER NOT NULL DEFAULT 0,
    backups_available INTEGER NOT NULL DEFAULT 0,
    end_of_life INTEGER NOT NULL DEFAULT 0,

    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,

    findings TEXT NOT NULL,
    recommendations TEXT NOT NULL,
    positive_controls TEXT NOT NULL,
    ai_analysis TEXT,

created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);