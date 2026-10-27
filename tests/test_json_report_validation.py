import json
import pytest

SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")


@pytest.fixture
def report():
    findings = [
        {
            "module": "HTTP Security Headers",
            "title": "CSP Allows unsafe-eval",
            "category": "Security Misconfiguration",
            "severity": "Low",
            "confidence": "High",
            "evidence": "An enforced CSP contains unsafe-eval.",
            "description": "Dynamic code evaluation is permitted.",
            "recommendation": "Remove unsafe-eval if not required.",
            "status": "Observation",
        },
        {
            "module": "Cookie Security",
            "title": "Cookie Missing SameSite Attribute",
            "category": "Cookie Misconfiguration",
            "severity": "Low",
            "confidence": "Medium",
            "evidence": "Cookie name: GPS",
            "description": "The cookie has no explicit SameSite policy.",
            "recommendation": "Configure an appropriate SameSite policy.",
            "status": "Observation",
        },
    ]

    severity_counts = {
        severity: sum(
            item["severity"] == severity for item in findings
        )
        for severity in SEVERITIES
    }

    return {
        "project": "VulnX",
        "version": "0.4",
        "report_status": "completed",
        "summary": {
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "modules_with_findings": sorted(
                {item["module"] for item in findings}
            ),
        },
        "findings": findings,
        "database_error_findings": [],
    }


def test_json_serialization(report):
    restored = json.loads(json.dumps(report))

    assert restored["project"] == "VulnX"
    assert restored["report_status"] == "completed"


def test_total_findings(report):
    assert report["summary"]["total_findings"] == len(
        report["findings"]
    )


def test_severity_counts(report):
    for severity in SEVERITIES:
        expected = sum(
            item["severity"] == severity
            for item in report["findings"]
        )

        assert report["summary"]["severity_counts"][severity] == expected


def test_modules_with_findings(report):
    expected = sorted(
        {item["module"] for item in report["findings"]}
    )

    assert report["summary"]["modules_with_findings"] == expected


def test_required_finding_fields(report):
    required = {
        "module",
        "title",
        "category",
        "severity",
        "confidence",
        "evidence",
        "description",
        "recommendation",
        "status",
    }

    for finding in report["findings"]:
        assert required.issubset(finding.keys())


def test_empty_findings():
    findings = []
    counts = {
        severity: sum(
            item["severity"] == severity for item in findings
        )
        for severity in SEVERITIES
    }

    assert len(findings) == 0
    assert sum(counts.values()) == 0