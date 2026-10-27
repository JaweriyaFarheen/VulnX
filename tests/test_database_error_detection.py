
from scanner.checks.sql_injection import analyze_database_errors


def test_detects_mysql_error():
    body = (
        "You have an error in your SQL syntax; "
        "check the manual that corresponds to your MySQL server version."
    )

    findings = analyze_database_errors(
        url="https://example.com/",
        body=body,
    )

    assert len(findings) >= 1
    assert any("MySQL" in finding.description for finding in findings)


def test_detects_postgresql_error():
    body = "ERROR: syntax error at or near SELECT"

    findings = analyze_database_errors(
        url="https://example.com/",
        body=body,
    )

    assert len(findings) >= 1
    assert any("PostgreSQL" in finding.description for finding in findings)


def test_detects_sql_server_error():
    body = "Microsoft SQL Server reported an Error."

    findings = analyze_database_errors(
        url="https://example.com/",
        body=body,
    )

    assert len(findings) >= 1
    assert any(
        "Microsoft SQL Server" in finding.description
        for finding in findings
    )


def test_detects_oracle_error():
    body = "ORA-01756: quoted string not properly terminated"

    findings = analyze_database_errors(
        url="https://example.com/",
        body=body,
    )

    assert len(findings) >= 1
    assert any("Oracle" in finding.description for finding in findings)


def test_detects_sqlite_error():
    body = 'sqlite3.OperationalError: near "SELECT": syntax error'

    findings = analyze_database_errors(
        url="https://example.com/",
        body=body,
    )

    assert len(findings) >= 1
    assert any("SQLite" in finding.description for finding in findings)


def test_normal_response_has_no_database_error():
    body = "<html><body>Welcome to our website!</body></html>"

    findings = analyze_database_errors(
        url="https://example.com/",
        body=body,
    )

    assert findings == []


def test_database_product_mention_is_not_enough():
    body = "This application uses MySQL and PostgreSQL databases."

    findings = analyze_database_errors(
        url="https://example.com/",
        body=body,
    )

    assert findings == []


def test_empty_body_returns_no_findings():
    findings = analyze_database_errors(
        url="https://example.com/",
        body="",
    )

    assert findings == []


def test_empty_url_returns_no_findings():
    findings = analyze_database_errors(
        url="",
        body="ORA-01756: quoted string not properly terminated",
    )

    assert findings == []
