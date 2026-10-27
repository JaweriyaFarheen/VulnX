"""
VulnX - Advanced Web Vulnerability Scanner
Interactive Security Dashboard
"""

import json
import ipaddress
import socket
from urllib.parse import urlsplit
from datetime import datetime, timezone
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether

import pandas as pd
import streamlit as st

from scanner.core.engine import run_scan
from scanner.core.reporting import SEVERITY_ORDER, build_report


def get_public_ip_addresses(url: str | None) -> list[str]:
    """Return globally routable IPs observed from a URL hostname lookup.

    This is a report-time DNS lookup, not proof of the exact IP used by the
    scanner's pinned connection. Results can change with DNS/load balancing.
    """
    if not url:
        return []

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        if not hostname:
            return []

        # If the hostname is already an IP literal, validate it directly.
        try:
            ip_obj = ipaddress.ip_address(hostname)
            return [str(ip_obj)] if ip_obj.is_global else []
        except ValueError:
            pass

        results = socket.getaddrinfo(
            hostname,
            parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
            type=socket.SOCK_STREAM,
        )
        public_ips = set()
        for item in results:
            address = item[4][0]
            try:
                ip_obj = ipaddress.ip_address(address)
            except ValueError:
                continue
            if ip_obj.is_global:
                public_ips.add(str(ip_obj))

        # Stable ordering makes reports easier to compare.
        return sorted(public_ips)
    except (OSError, ValueError, UnicodeError):
        return []


def build_pdf_report(report: dict) -> bytes:
    """Create a readable PDF report from the structured VulnX report."""
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
        title="VulnX Security Assessment Report",
        author="VulnX",
    )

    base_styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "VulnXTitle",
        parent=base_styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=21,
        leading=26,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#12304A"),
        spaceAfter=8,
    )
    section_style = ParagraphStyle(
        "VulnXSection",
        parent=base_styles["Heading2"],
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#12304A"),
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "VulnXBody",
        parent=base_styles["BodyText"],
        fontSize=9,
        leading=12,
        spaceAfter=4,
        wordWrap="CJK",
    )
    small_style = ParagraphStyle(
        "VulnXSmall",
        parent=body_style,
        fontSize=8,
        leading=10,
    )

    def safe(value) -> str:
        if value is None or value == "":
            return "Not available"
        return escape(str(value)).replace("\n", "<br/>")

    story = [
        Paragraph("VulnX Security Assessment Report", title_style),
        Paragraph("Automated findings are observations and require verification.", body_style),
        Spacer(1, 8),
        Paragraph("Scan Details", section_style),
    ]

    detail_rows = [
        ["Target", safe(report.get("target"))],
        ["Target IP address(es)", safe(", ".join(report.get("target_ip_addresses", [])))],
        ["Final URL", safe(report.get("final_url"))],
        ["Final IP address(es)", safe(", ".join(report.get("final_ip_addresses", [])))],
        ["HTTP Status", safe(report.get("http_status"))],
        ["Report Status", safe(report.get("report_status"))],
        ["Generated (UTC)", safe(report.get("scan_timestamp_utc"))],
        ["VulnX Version", safe(report.get("version"))],
    ]
    details_table = Table(detail_rows, colWidths=[1.35 * inch, 5.55 * inch], repeatRows=0)
    details_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EAF0F5")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#17212B")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#C8D2DC")),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.extend([details_table, Paragraph("Summary", section_style)])

    summary = report.get("summary", {})
    severity_counts = summary.get("severity_counts", {})
    summary_rows = [["Metric", "Count"]]
    summary_rows.append(["Total Findings", str(summary.get("total_findings", 0))])
    for severity, count in severity_counts.items():
        summary_rows.append([safe(severity), str(count)])
    summary_table = Table(summary_rows, colWidths=[3.45 * inch, 3.45 * inch], repeatRows=1)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12304A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#C8D2DC")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F8FA")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.extend([summary_table, Paragraph("Findings and Remediation", section_style)])

    findings = report.get("findings", [])
    if not findings:
        story.append(Paragraph("No findings were recorded by the enabled checks for this scan.", body_style))
    else:
        for index, finding in enumerate(findings, start=1):
            heading = (
                f"{index}. {safe(finding.get('title'))} "
                f"({safe(finding.get('severity'))})"
            )
            content = [
                Paragraph(heading, base_styles["Heading3"]),
                Paragraph(f"<b>Module:</b> {safe(finding.get('module'))}", body_style),
                Paragraph(f"<b>Category:</b> {safe(finding.get('category'))}", body_style),
                Paragraph(f"<b>Confidence:</b> {safe(finding.get('confidence'))}", body_style),
                Paragraph(f"<b>Status:</b> {safe(finding.get('status'))}", body_style),
                Paragraph(f"<b>Evidence:</b> {safe(finding.get('evidence'))}", body_style),
                Paragraph(f"<b>Description:</b> {safe(finding.get('description'))}", body_style),
                Paragraph(f"<b>Recommended remediation:</b> {safe(finding.get('recommendation'))}", body_style),
                Spacer(1, 6),
            ]
            story.append(KeepTogether(content))

    tls_info = report.get("tls_analysis")
    if tls_info:
        story.append(Paragraph("TLS Details", section_style))
        for label in ("hostname", "port", "tls_version", "cipher", "certificate_expires", "error"):
            if tls_info.get(label) not in (None, ""):
                story.append(Paragraph(f"<b>{label.replace('_', ' ').title()}:</b> {safe(tls_info.get(label))}", body_style))

    limitations = report.get("limitations", [])
    if limitations:
        story.append(Paragraph("Limitations", section_style))
        for limitation in limitations:
            story.append(Paragraph(f"- {safe(limitation)}", small_style))

    def add_page_number(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#667788"))
        canvas.drawString(0.65 * inch, 0.35 * inch, "VulnX - Authorized security assessment")
        canvas.drawRightString(letter[0] - 0.65 * inch, 0.35 * inch, f"Page {doc.page}")
        canvas.restoreState()

    document.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
    return buffer.getvalue()


# ==========================================================
# PAGE CONFIGURATION
# ==========================================================

st.set_page_config(
    page_title="VulnX | Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ==========================================================
# CUSTOM STYLING
# ==========================================================

st.markdown(
    """
    <style>
    .main-title {
        font-size: 42px;
        font-weight: 800;
        color: #36CFC9;
        margin-bottom: 0;
    }

    .subtitle {
        font-size: 16px;
        color: #A7B0C0;
        margin-top: 4px;
        margin-bottom: 25px;
    }

    .stMetric {
        background-color: rgba(54, 207, 201, 0.06);
        padding: 12px;
        border-radius: 10px;
        border: 1px solid rgba(54, 207, 201, 0.2);
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ==========================================================
# HEADER
# ==========================================================

st.markdown(
    '<div class="main-title">🛡️ VulnX</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="subtitle">'
    'Advanced Web Application Security Scanner'
    '</div>',
    unsafe_allow_html=True,
)

st.info(
    "Authorized security testing only. VulnX currently performs "
    "HTTP security-header analysis, cookie attribute analysis, "
    "passive database error disclosure detection, and TLS "
    "certificate inspection. Database error detection does not "
    "by itself prove exploitable SQL injection."
)


# ==========================================================
# SIDEBAR
# ==========================================================

with st.sidebar:

    st.header("⚙️ Scan Configuration")

    target_url = st.text_input(
        "Target URL",
        placeholder="https://example.com",
        help="Enter the complete HTTP or HTTPS URL.",
    )

    st.caption(
        "Non-public destinations are rejected by the current validator."
    )

    start_scan = st.button(
        "🔍 Start Scan",
        use_container_width=True,
        type="primary",
    )

    st.divider()

    st.subheader("Detection Modules")

    st.markdown(
        """
        - 🌐 HTTP response analysis
        - 🛡️ Security header checks
        - 🍪 Cookie security analysis
        - 🗄️ Database error disclosure detection
        - 🔐 TLS certificate inspection
        - 📋 Evidence and remediation
        - 📥 JSON report export
        """
    )

    st.divider()

    st.caption("VulnX Development Version 0.4")


# ==========================================================
# DASHBOARD OVERVIEW
# ==========================================================

st.subheader("Security Assessment Dashboard")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Scanner", "Ready")
col2.metric("Detection Modules", "4")
col3.metric("Last Verified Tests", "108 passed")
col4.metric("Scan Mode", "Basic")

st.caption(
    "The test count is informational and is not a live test result."
)


# ==========================================================
# SCAN EXECUTION
# ==========================================================

if start_scan:

    st.session_state.pop("last_scan", None)

    if not target_url.strip():

        st.error("Please enter a target URL.")

    else:

        try:

            with st.spinner(
                "Validating target and analyzing security..."
            ):

                result = run_scan(target_url.strip())

            # Always retain the result, even when the HTTP request fails.
            # TLS inspection may still have produced useful structured findings.
            st.session_state["last_scan"] = result

            if result.error:
                st.warning(
                    f"HTTP request did not complete successfully: {result.error}"
                )

        except Exception as exc:

            st.error(
                "An unexpected error occurred: "
                f"{type(exc).__name__}"
            )


# ==========================================================
# SCAN RESULTS
# ==========================================================

result = st.session_state.get("last_scan")

if result:

    st.divider()

    st.subheader("📊 Latest Scan Results")

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "HTTP Status",
        (
            result.status_code
            if result.status_code is not None
            else "Unavailable"
        ),
    )

    tls = result.tls_result

    tls_findings = (
        tls.findings if tls is not None else []
    )

    database_error_findings = getattr(
        result, "database_error_findings", []
    )

    total_findings = (
        len(result.findings)
        + len(result.cookie_findings)
        + len(database_error_findings)
        + len(tls_findings)
    )

    col2.metric("Total Observations", total_findings)

    col3.metric(
        "Request Status",
        "Completed" if result.final_url else "Unavailable",
    )

    st.write("**Requested URL:**", result.target_url)

    if result.final_url:
        st.write("**Final URL:**", result.final_url)

    # ------------------------------------------------------
    # HTTP SECURITY FINDINGS
    # ------------------------------------------------------

    st.divider()

    st.subheader("🛡️ HTTP Security Findings")

    if result.findings:

        http_data = [
            {
                "Finding": finding.title,
                "Severity": finding.severity,
                "Confidence": finding.confidence,
                "Category": finding.category,
                "Status": finding.status,
            }
            for finding in result.findings
        ]

        st.dataframe(
            pd.DataFrame(http_data),
            use_container_width=True,
            hide_index=True,
        )

        for index, finding in enumerate(
            result.findings,
            start=1,
        ):

            with st.expander(
                f"{index}. {finding.title} — {finding.severity}"
            ):

                st.write("**Category:**", finding.category)
                st.write("**Severity:**", finding.severity)
                st.write("**Confidence:**", finding.confidence)
                st.write("**Status:**", finding.status)

                st.write("**Evidence**")
                st.code(finding.evidence, language="text")

                st.write("**Description**")
                st.write(finding.description)

                st.write("**Recommended Remediation**")
                st.write(finding.recommendation)

    else:

        st.success("No HTTP findings were generated.")

    # ------------------------------------------------------
    # COOKIE SECURITY FINDINGS
    # ------------------------------------------------------

    st.divider()

    st.subheader("🍪 Cookie Security Analysis")

    if result.cookie_findings:

        cookie_data = [
            {
                "Finding": finding.title,
                "Cookie": finding.cookie_name,
                "Severity": finding.severity,
                "Confidence": finding.confidence,
            }
            for finding in result.cookie_findings
        ]

        st.dataframe(
            pd.DataFrame(cookie_data),
            use_container_width=True,
            hide_index=True,
        )

        for index, finding in enumerate(
            result.cookie_findings,
            start=1,
        ):

            with st.expander(
                f"{index}. {finding.title} — {finding.cookie_name}"
            ):

                st.write("**Severity:**", finding.severity)
                st.write("**Confidence:**", finding.confidence)

                st.write("**Evidence**")
                st.code(finding.evidence, language="text")

                st.write("**Description**")
                st.write(finding.description)

                st.write("**Recommended Remediation**")
                st.write(finding.recommendation)

    else:

        st.info(
            "No cookie security observations were generated. "
            "The response may not have set any cookies."
        )

    # ------------------------------------------------------
    # DATABASE ERROR DISCLOSURE FINDINGS
    # ------------------------------------------------------

    st.divider()

    st.subheader("🗄️ Database Error Disclosure Analysis")

    if database_error_findings:

        database_data = [
            {
                "Finding": finding.title,
                "Severity": finding.severity,
                "Confidence": finding.confidence,
                "Category": finding.category,
            }
            for finding in database_error_findings
        ]

        st.dataframe(
            pd.DataFrame(database_data),
            use_container_width=True,
            hide_index=True,
        )

        for index, finding in enumerate(
            database_error_findings,
            start=1,
        ):

            with st.expander(
                f"{index}. {finding.title} — {finding.severity}"
            ):

                st.write("**Category:**", finding.category)
                st.write("**Severity:**", finding.severity)
                st.write("**Confidence:**", finding.confidence)

                st.write("**Evidence**")
                st.code(finding.evidence, language="text")

                st.write("**Description**")
                st.write(finding.description)

                st.write("**Recommended Remediation**")
                st.write(finding.recommendation)

        st.warning(
            "Database error signatures can disclose implementation details, "
            "but this passive check does not confirm exploitable SQL injection."
        )

    else:

        st.success(
            "No recognizable database error signatures were detected "
            "in the response body. This does not rule out SQL injection."
        )

    # ------------------------------------------------------
    # TLS CERTIFICATE ANALYSIS
    # ------------------------------------------------------

    st.divider()

    st.subheader("🔐 TLS Certificate Analysis")

    if tls is None:

        if (
            result.final_url
            and result.final_url.lower().startswith("https://")
        ):

            st.warning(
                "TLS analysis did not return a result."
            )

        else:

            st.info(
                "TLS analysis is available for HTTPS targets."
            )

    else:

        tls_col1, tls_col2, tls_col3 = st.columns(3)

        tls_col1.metric(
            "TLS Version",
            tls.tls_version or "Unavailable",
        )

        tls_col2.metric(
            "Cipher",
            tls.cipher or "Unavailable",
        )

        tls_col3.metric(
            "Certificate Expiry",
            (
                tls.certificate_expires[:10]
                if tls.certificate_expires
                else "Unavailable"
            ),
        )

        if tls.error:

            st.warning(
                f"TLS inspection issue: {tls.error}"
            )

        if tls.findings:

            for index, finding in enumerate(
                tls.findings,
                start=1,
            ):

                with st.expander(
                    f"{index}. {finding.title} — {finding.severity}"
                ):

                    st.write("**Confidence:**", finding.confidence)
                    st.write("**Evidence:**", finding.evidence)
                    st.write("**Description:**", finding.description)

                    st.write(
                        "**Recommended Remediation:**",
                        finding.recommendation,
                    )

        elif not tls.error:

            st.success(
                "No certificate problems were detected "
                "by the current TLS checks."
            )

    # ------------------------------------------------------
    # JSON REPORT
    # ------------------------------------------------------

    st.divider()
    st.subheader("📥 Export Scan Report")

    target_ip_addresses = get_public_ip_addresses(result.target_url)
    final_ip_addresses = get_public_ip_addresses(result.final_url)

    report = build_report(
        target=result.target_url,
        final_url=result.final_url,
        http_status=result.status_code,
        http_findings=result.findings,
        cookie_findings=result.cookie_findings,
        database_error_findings=database_error_findings,
        tls_result=tls,
        target_ip_addresses=target_ip_addresses,
        final_ip_addresses=final_ip_addresses,
    )

    consolidated_findings = report["findings"]
    severity_counts = report["summary"]["severity_counts"]
    severity_order = SEVERITY_ORDER
    report_json = json.dumps(report, indent=2, ensure_ascii=False)

    st.subheader("Report Summary")
    summary_col1, summary_col2 = st.columns(2)
    summary_col1.metric("Total Findings", len(consolidated_findings))
    summary_col2.metric("Report Status", report["report_status"].title())

    severity_cols = st.columns(len(severity_order))
    for column, severity in zip(severity_cols, severity_order):
        column.metric(severity, severity_counts[severity])

    st.download_button(
        label="📄 Download Complete Scan Report (JSON)",
        data=report_json,
        file_name="vulnx_scan_report.json",
        mime="application/json",
        use_container_width=True,
    )

    try:
        report_pdf = build_pdf_report(report)
        st.download_button(
            label="📕 Download Security Assessment Report (PDF)",
            data=report_pdf,
            file_name="vulnx_security_assessment_report.pdf",
            mime="application/pdf",
            use_container_width=True,
        )
    except Exception as exc:
        st.error(
            "PDF report generation failed. "
            f"Error: {type(exc).__name__}: {exc}"
        )


# ==========================================================
# EMPTY STATE
# ==========================================================

else:

    st.divider()

    st.markdown(
        """
        ### Welcome to VulnX 👋

        Start an authorized assessment using the sidebar.

        Your report will include HTTP security findings,
        cookie security observations, database error disclosure analysis,
        and TLS analysis.
        """
    )


# ==========================================================
# FOOTER
# ==========================================================

st.divider()

st.caption(
    "VulnX is a development-stage security scanner. "
    "Automated findings require appropriate verification. "
    "Only scan systems you own or have permission to assess."
)