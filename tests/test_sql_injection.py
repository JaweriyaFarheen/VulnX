"""Tests for the database error disclosure analyzer."""

import pytest

from scanner.checks.sql_injection import (
    analyze_database_errors,
)


@pytest.mark.parametrize(
    "body",
    [
        "You have an error in your SQL syntax; check the manual "
        "that corresponds to your MySQL server version for the right syntax",
        "ERROR: syntax error at or near SELECT",
        "Unclosed quotation mark after the character string",
        "ORA-00933: SQL command not properly ended",
        'sqlite3.OperationalError: near "SELECT": syntax error',
    ],
)
def test_detects_database_error_signatures(body):
    findings = analyze_database_errors(
        "https://example.com/search",
        body,
    )

    assert findings
    assert findings[0].title == "Database Error Message Disclosed"
    assert findings[0].category == "Information Disclosure"
    assert findings[0].severity == "Medium"


@pytest.mark.parametrize(
    "body",
    [
        "<html><body>Welcome!</body></html>",
        "Your order has been processed successfully.",
        "We use MySQL to store application data.",
        "",
    ],
)
def test_ignores_normal_responses(body):
    findings = analyze_database_errors(
        "https://example.com/",
        body,
    )

    assert findings == []


@pytest.mark.parametrize(
    ("url", "body"),
    [
        ("", "ORA-00933: SQL command not properly ended"),
        ("https://example.com", None),
        ("https://example.com", 123),
        (None, "ORA-00933: SQL command not properly ended"),
    ],
)
def test_handles_invalid_inputs(url, body):
    findings = analyze_database_errors(url, body)

    assert findings == []


def test_finding_does_not_include_full_response():
    body = (
        "ORA-00933: SQL command not properly ended "
        "password=example-secret-value"
    )

    findings = analyze_database_errors(
        "https://example.com/",
        body,
    )

    assert findings
    assert "example-secret-value" not in findings[0].evidence


def test_finding_contains_remediation():
    findings = analyze_database_errors(
        "https://example.com/",
        "ORA-00933: SQL command not properly ended",
    )

    assert findings
    assert "parameterized SQL queries" in findings[0].recommendation