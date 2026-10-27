
"""Report-data utilities for VulnX."""

from datetime import datetime, timezone


SEVERITY_ORDER = (
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational",
)


def finding_to_dict(finding, module, default_category="Security Finding"):
    """Convert a finding object into a JSON-compatible dictionary."""

    return {
        "module": module,
        "title": finding.title,
        "category": getattr(finding, "category", default_category),
        "severity": finding.severity,
        "confidence": finding.confidence,
        "evidence": finding.evidence,
        "description": finding.description,
        "recommendation": finding.recommendation,
        "status": getattr(finding, "status", "Observation"),
    }


def calculate_severity_counts(findings):
    """Count findings by severity while preserving unknown labels."""

    counts = {severity: 0 for severity in SEVERITY_ORDER}

    for finding in findings:
        severity = str(finding.get("severity", "Unknown"))

        matching_key = next(
            (
                key
                for key in counts
                if key.casefold() == severity.casefold()
            ),
            None,
        )

        if matching_key is None:
            matching_key = severity

        counts[matching_key] = counts.get(matching_key, 0) + 1

    return counts


def build_report(
    target,
    final_url,
    http_status,
    http_findings=None,
    cookie_findings=None,
    database_error_findings=None,
    tls_result=None,
    target_ip_addresses=None,
    final_ip_addresses=None,
):
    """Build the consolidated VulnX report dictionary."""

    http_findings = list(http_findings or [])
    cookie_findings = list(cookie_findings or [])
    database_error_findings = list(database_error_findings or [])
    target_ip_addresses = list(target_ip_addresses or [])
    final_ip_addresses = list(final_ip_addresses or [])

    findings = []

    for finding in http_findings:
        findings.append(
            finding_to_dict(
                finding,
                "HTTP Security Headers",
            )
        )

    for finding in cookie_findings:
        findings.append(
            finding_to_dict(
                finding,
                "Cookie Security",
                "Cookie Misconfiguration",
            )
        )

    for finding in database_error_findings:
        findings.append(
            finding_to_dict(
                finding,
                "Database Error Disclosure",
                "Information Disclosure",
            )
        )

    tls_report = None

    if tls_result is not None:
        tls_findings = []

        for finding in getattr(tls_result, "findings", []):
            item = finding_to_dict(
                finding,
                "TLS Certificate Inspection",
                "TLS Configuration",
            )
            findings.append(item)

            tls_findings.append(
                {
                    key: value
                    for key, value in item.items()
                    if key != "module"
                }
            )

        tls_report = {
            "hostname": getattr(tls_result, "hostname", None),
            "port": getattr(tls_result, "port", None),
            "tls_version": getattr(tls_result, "tls_version", None),
            "cipher": getattr(tls_result, "cipher", None),
            "certificate_expires": getattr(
                tls_result,
                "certificate_expires",
                None,
            ),
            "error": getattr(tls_result, "error", None),
            "findings": tls_findings,
        }

    severity_counts = calculate_severity_counts(findings)

    cookie_report = []

    for source_finding in cookie_findings:
        item = finding_to_dict(
            source_finding,
            "Cookie Security",
            "Cookie Misconfiguration",
        )
        item.pop("module")

        item["cookie_name"] = getattr(
            source_finding,
            "cookie_name",
            None,
        )

        cookie_report.append(item)

    return {
        "project": "VulnX",
        "version": "0.4",
        "report_status": "completed" if final_url else "incomplete",
        "scan_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "target_ip_addresses": target_ip_addresses,
        "final_url": final_url,
        "final_ip_addresses": final_ip_addresses,
        "ip_lookup_note": (
            "These public IP addresses were resolved when the report "
            "was generated. DNS answers can change and may differ from "
            "the exact IP used for the scan."
        ),
        "http_status": http_status,
        "summary": {
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "modules_with_findings": sorted(
                {
                    finding["module"]
                    for finding in findings
                }
            ),
        },
        "findings": findings,
        "http_findings": [
            {
                key: value
                for key, value in finding.items()
                if key != "module"
            }
            for finding in findings
            if finding["module"] == "HTTP Security Headers"
        ],
        "cookie_findings": cookie_report,
        "database_error_findings": [
            {
                key: value
                for key, value in finding.items()
                if key != "module"
            }
            for finding in findings
            if finding["module"] == "Database Error Disclosure"
        ],
        "tls_analysis": tls_report,
        "limitations": [
            "Findings are automated observations and require verification.",
            (
                "Passive database error detection does not prove "
                "exploitable SQL injection."
            ),
            "No findings does not guarantee that a target is secure.",
        ],
    }
