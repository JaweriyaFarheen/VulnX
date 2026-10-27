"""
VulnX - Database Error Disclosure Analyzer

Passively detects database error messages in HTTP response bodies.

Important:
- Does not send SQL injection payloads.
- Database errors indicate possible information disclosure.
- Detection does not prove SQL injection is exploitable.
"""

from dataclasses import dataclass
import re


@dataclass
class SQLInjectionFinding:
    """Represents a possible database error disclosure."""

    title: str
    category: str
    severity: str
    confidence: str
    evidence: str
    description: str
    recommendation: str


# Patterns identify recognizable database error messages.
# They intentionally avoid treating ordinary mentions of database
# products as findings.
DATABASE_ERROR_PATTERNS = {
    "MySQL": re.compile(
        r"(?:SQL syntax.*MySQL|"
        r"Warning:\s*mysql_.*|"
        r"MySQL server version for the right syntax)",
        re.IGNORECASE,
    ),
    "PostgreSQL": re.compile(
        r"(?:PostgreSQL.*ERROR|"
        r"ERROR:\s*syntax error at or near|"
        r"pg_query\(\).*failed)",
        re.IGNORECASE,
    ),
    "Microsoft SQL Server": re.compile(
        r"(?:Microsoft SQL Server.*Error|"
        r"Unclosed quotation mark after the character string|"
        r"Incorrect syntax near)",
        re.IGNORECASE,
    ),
    "Oracle": re.compile(
        r"(?:ORA-\d{5}|"
        r"Oracle error)",
        re.IGNORECASE,
    ),
    "SQLite": re.compile(
        r"(?:SQLite/JDBCDriver|"
        r"SQLite.Exception|"
        r"sqlite3\.OperationalError|"
        r"near \".*\": syntax error)",
        re.IGNORECASE,
    ),
}


def analyze_database_errors(
    url: str,
    body: str,
) -> list[SQLInjectionFinding]:
    """
    Inspect a response body for recognizable database error messages.

    Args:
        url: URL associated with the response.
        body: Response body text.

    Returns:
        Database error disclosure findings.
    """

    findings: list[SQLInjectionFinding] = []

    if not isinstance(url, str) or not url.strip():
        return findings

    if not isinstance(body, str) or not body:
        return findings

    for database, pattern in DATABASE_ERROR_PATTERNS.items():
        match = pattern.search(body)

        if not match:
            continue

        # Keep evidence short and avoid including the full response,
        # which might contain secrets or user data.
        evidence = (
            f"Response contains a recognizable "
            f"{database} database error signature."
        )

        findings.append(
            SQLInjectionFinding(
                title="Database Error Message Disclosed",
                category="Information Disclosure",
                severity="Medium",
                confidence="Medium",
                evidence=evidence,
                description=(
                    f"The response contains a pattern associated with "
                    f"a {database} database error. Detailed errors can "
                    "reveal implementation information. This observation "
                    "does not independently prove SQL injection."
                ),
                recommendation=(
                    "Return generic error messages to users. Log "
                    "technical details securely on the server, use "
                    "parameterized SQL queries, and investigate the "
                    "request that triggered the error."
                ),
            )
        )

    return findings