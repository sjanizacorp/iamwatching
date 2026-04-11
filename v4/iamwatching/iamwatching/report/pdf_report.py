"""
PDF Report Generator for IamWatching
=====================================
Generates a clean, professional PDF security audit report using ReportLab Platypus.

Key design decisions to prevent garbled text and overruns:
- All text is sanitised (non-ASCII stripped, XML entities escaped) before rendering
- Long strings (ARNs, JSON) are wrapped or truncated with visual indicator
- Tables use fixed column widths that sum to the available content area
- All Paragraph text uses HTML-safe escaping via rl_safe()
- No Unicode special characters in font-rendered text (uses ReportLab XML markup instead)
- Cell content is truncated at word boundary to prevent overflow
"""
from __future__ import annotations

import html
import json
import re
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

# ── Layout constants ──────────────────────────────────────────────────────────
PAGE_W, PAGE_H = letter           # 8.5 x 11 inches
L_MARGIN = R_MARGIN = 0.75 * inch
T_MARGIN = B_MARGIN = 0.75 * inch
CONTENT_W = PAGE_W - L_MARGIN - R_MARGIN   # 7.0 inches

# ── Brand colours ─────────────────────────────────────────────────────────────
NAVY    = colors.HexColor("#1F3864")
BLUE    = colors.HexColor("#2B6CB0")
LBLUE   = colors.HexColor("#EBF4FF")
GREEN   = colors.HexColor("#276749")
LGREEN  = colors.HexColor("#F0FFF4")
RED     = colors.HexColor("#C53030")
LRED    = colors.HexColor("#FFF5F5")
AMBER   = colors.HexColor("#B7791F")
LAMBER  = colors.HexColor("#FFFFF0")
GREY    = colors.HexColor("#718096")
LGREY   = colors.HexColor("#F7FAFC")
DGREY   = colors.HexColor("#2D3748")
WHITE   = colors.white
BLACK   = colors.HexColor("#1A202C")

SEVERITY_BG: dict[str, colors.Color] = {
    "CRITICAL": colors.HexColor("#FED7D7"),
    "HIGH":     colors.HexColor("#FEEBC8"),
    "MEDIUM":   colors.HexColor("#FEFCBF"),
    "LOW":      colors.HexColor("#E9D8FD"),
    "INFO":     colors.HexColor("#BEE3F8"),
}
SEVERITY_FG: dict[str, colors.Color] = {
    "CRITICAL": RED,
    "HIGH":     AMBER,
    "MEDIUM":   colors.HexColor("#744210"),
    "LOW":      colors.HexColor("#553C9A"),
    "INFO":     BLUE,
}


# ── Text helpers ──────────────────────────────────────────────────────────────

def _safe(text: str, max_len: int = 0) -> str:
    """
    Make text safe for ReportLab Paragraph rendering:
    1. Convert to str
    2. Strip non-printable / non-ASCII control chars (causes garbled glyphs)
    3. Escape XML/HTML special characters (<, >, &, ", ')
    4. Optionally truncate to max_len characters
    """
    if text is None:
        return ""
    text = str(text)
    # Strip non-printable chars (keep ASCII 32-126 + newline/tab)
    text = re.sub(r"[^\x20-\x7E\n\t]", " ", text)
    # Escape XML entities so ReportLab's XML parser doesn't choke
    text = html.escape(text, quote=False)
    if max_len and len(text) > max_len:
        text = text[:max_len - 3] + "..."
    return text.strip()


def _wrap_arn(arn: str, width: int = 55) -> str:
    """
    Break a long ARN / resource ID at logical boundaries so it fits in a cell.
    Uses soft hyphen positions (colon, slash) and falls back to hard wrap.
    """
    arn = _safe(arn)
    if len(arn) <= width:
        return arn
    # Insert newlines after natural break points
    parts = re.split(r"(?<=[:\/])", arn)
    lines, current = [], ""
    for part in parts:
        if len(current) + len(part) > width:
            if current:
                lines.append(current)
            current = part
        else:
            current += part
    if current:
        lines.append(current)
    return "\n".join(lines)


def _sev(finding: dict) -> str:
    """Extract clean severity string from a finding dict."""
    raw = str(finding.get("severity", "INFO"))
    if "." in raw:
        raw = raw.split(".")[-1]
    return raw.upper()


# ── Console URL generator ─────────────────────────────────────────────────────

def _console_url(arn: str, region: str = "") -> str:
    """
    Return a direct browser URL for the given AWS/Azure/GCP resource identifier.
    Returns "" for unrecognised formats rather than a broken link.
    """
    arn = str(arn).strip()
    region = str(region).strip() or "us-east-1"
    if not arn:
        return ""

    # ── AWS ARN ────────────────────────────────────────────────────────────
    if arn.startswith("arn:aws"):
        parts = arn.split(":")
        if len(parts) < 6:
            return ""
        service    = parts[2]
        arn_region = parts[3] or region
        resource   = ":".join(parts[5:])
        base       = "https://console.aws.amazon.com"

        if service == "iam":
            if "user/" in resource:
                name = resource.split("user/", 1)[-1]
                return f"{base}/iam/home#/users/details/{name}"
            if "role/" in resource:
                name = resource.split("role/", 1)[-1].split("/")[0]
                return f"{base}/iam/home#/roles/details/{name}"
            if "group/" in resource:
                name = resource.split("group/", 1)[-1]
                return f"{base}/iam/home#/groups/{name}"
            if "policy/" in resource:
                return f"{base}/iam/home#/policies/{arn}"
            if resource in ("root", ":root"):
                return f"{base}/iam/home#/security_credentials"
            return f"{base}/iam/home"
        if service == "s3":
            bucket = resource.split("/")[0]
            return f"https://s3.console.aws.amazon.com/s3/buckets/{bucket}?region={arn_region}"
        if service == "lambda":
            fn = resource.split("function:")[-1].split(":")[0] if "function:" in resource else resource
            return f"{base}/lambda/home?region={arn_region}#/functions/{fn}"
        if service == "ec2":
            if "instance/" in resource:
                iid = resource.split("instance/", 1)[-1]
                return f"{base}/ec2/home?region={arn_region}#Instances:instanceId={iid}"
            if "security-group/" in resource:
                sg = resource.split("security-group/", 1)[-1]
                return f"{base}/ec2/home?region={arn_region}#SecurityGroups:groupId={sg}"
            return f"{base}/ec2/home?region={arn_region}"
        if service == "ecs":
            if "task-definition/" in resource:
                td = resource.split("task-definition/", 1)[-1].split(":")[0]
                return f"{base}/ecs/home?region={arn_region}#/taskDefinitions/{td}"
            return f"{base}/ecs/home?region={arn_region}#/taskDefinitions"
        if service == "cloudtrail":
            return f"{base}/cloudtrail/home?region={arn_region}#/trails"
        if service == "cloudwatch":
            return f"{base}/cloudwatch/home?region={arn_region}#alarmsV2"
        if service == "config":
            return f"{base}/config/home?region={arn_region}"
        return f"{base}/console/home?region={arn_region}"

    # ── Azure resource ID ──────────────────────────────────────────────────
    if arn.startswith("/subscriptions/"):
        encoded = arn.replace(" ", "%20")
        return f"https://portal.azure.com/#@/resource{encoded}/overview"

    # ── GCP resource path ──────────────────────────────────────────────────
    if arn.startswith("projects/"):
        m = re.match(r"projects/([^/]+)", arn)
        proj = m.group(1) if m else ""
        if "functions" in arn:
            fn = arn.split("/functions/")[-1] if "/functions/" in arn else ""
            return f"https://console.cloud.google.com/functions/details/{region}/{fn}?project={proj}"
        if "instances" in arn:
            inst = arn.split("/instances/")[-1] if "/instances/" in arn else ""
            return f"https://console.cloud.google.com/compute/instancesDetail/zones/{region}/instances/{inst}?project={proj}"
        return f"https://console.cloud.google.com/home/dashboard?project={proj}"

    return ""


# ── Resource identity normaliser ──────────────────────────────────────────────
#
# Checks return wildly different column names for the same concept.
# These priority lists map every known alias to a canonical field.

_ARN_COLS  = [
    "user_arn", "role_arn", "resource_arn", "bucket_arn", "instance_arn",
    "principal_arn", "root_arn", "root_account", "resource_id",
    "principal", "trusting_role", "trusted_by", "execution_role",
    "support_role", "resource", "task_definition",
]
_NAME_COLS = [
    "username", "role_name", "bucket_name", "instance_name",
    "resource_name", "name", "object_id", "email",
]
_TYPE_COLS   = ["resource_type", "type", "cloud", "resource_cloud"]
_REGION_COLS = ["region"]
_ISSUE_COLS  = ["issue", "action", "status", "inventory_item", "trust_type"]


def _pick(record: dict, keys: list) -> str:
    """Return the first non-empty value matching any key in keys."""
    for k in keys:
        v = record.get(k)
        if v is not None:
            s = str(v).strip()
            if s and s.lower() not in ("none", "null"):
                return s
    return ""


def _extract_identity(record: dict) -> dict:
    """
    Normalise any finding record dict into a canonical identity dict with:
      arn, name, rtype, region, issue, url
    Works regardless of which column names the Cypher query used.
    """
    arn    = _pick(record, _ARN_COLS)
    name   = _pick(record, _NAME_COLS)
    rtype  = _pick(record, _TYPE_COLS)
    region = _pick(record, _REGION_COLS)
    issue  = _pick(record, _ISSUE_COLS)

    # Derive name from ARN tail when the query didn't return a separate name column
    if not name and arn:
        tail = re.split(r"[:/]", arn)[-1]
        if tail and tail != arn:
            name = tail

    url = _console_url(arn, region)

    return {
        "arn":    arn,
        "name":   name,
        "rtype":  rtype,
        "region": region,
        "issue":  issue,
        "url":    url,
    }


# ── Style factory ─────────────────────────────────────────────────────────────

def _make_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()

    def ps(name, parent="Normal", **kw) -> ParagraphStyle:
        return ParagraphStyle(name, parent=base[parent], **kw)

    return {
        "cover_org":   ps("cover_org",   fontSize=10, textColor=GREY,  spaceAfter=4,  alignment=TA_CENTER),
        "cover_title": ps("cover_title", fontSize=28, textColor=NAVY,  spaceAfter=6,  alignment=TA_CENTER, leading=34, fontName="Helvetica-Bold"),
        "cover_sub":   ps("cover_sub",   fontSize=14, textColor=BLUE,  spaceAfter=4,  alignment=TA_CENTER),
        "cover_date":  ps("cover_date",  fontSize=10, textColor=GREY,  spaceAfter=0,  alignment=TA_CENTER),
        "h1":          ps("h1",          fontSize=16, textColor=NAVY,  spaceBefore=18, spaceAfter=8,  fontName="Helvetica-Bold", leading=20),
        "h2":          ps("h2",          fontSize=13, textColor=BLUE,  spaceBefore=12, spaceAfter=6,  fontName="Helvetica-Bold", leading=16),
        "h3":          ps("h3",          fontSize=11, textColor=DGREY, spaceBefore=8,  spaceAfter=4,  fontName="Helvetica-Bold"),
        "body":        ps("body",        fontSize=10, textColor=BLACK, spaceBefore=3,  spaceAfter=4,  leading=14),
        "small":       ps("small",       fontSize=8,  textColor=GREY,  spaceBefore=2,  spaceAfter=2,  leading=11),
        "code":        ps("code",        fontSize=8,  textColor=DGREY, spaceBefore=2,  spaceAfter=2,  leading=11, fontName="Courier"),
        "label":       ps("label",       fontSize=9,  textColor=GREY,  spaceBefore=0,  spaceAfter=1,  fontName="Helvetica-Bold"),
        "rec":         ps("rec",         fontSize=9,  textColor=GREEN, spaceBefore=2,  spaceAfter=2,  leading=13),
        "tbl_hdr":     ps("tbl_hdr",     fontSize=9,  textColor=WHITE, fontName="Helvetica-Bold", leading=12),
        "tbl_cell":    ps("tbl_cell",    fontSize=8,  textColor=BLACK, leading=11),
        "tbl_arn":     ps("tbl_arn",     fontSize=7,  textColor=DGREY, leading=10, fontName="Courier"),
        "tbl_url":     ps("tbl_url",     fontSize=7,  textColor=colors.HexColor("#2B6CB0"), leading=10),
        "ne_cell":     ps("ne_cell",     fontSize=8,  textColor=GREY,  leading=11, fontName="Helvetica-Oblique"),
        "sev_badge":   ps("sev_badge",   fontSize=9,  fontName="Helvetica-Bold", alignment=TA_CENTER, leading=11),
        "footer":      ps("footer",      fontSize=8,  textColor=GREY,  alignment=TA_CENTER),
        "exec_num":    ps("exec_num",    fontSize=24, textColor=NAVY,  fontName="Helvetica-Bold", alignment=TA_CENTER, leading=28),
        "exec_label":  ps("exec_label",  fontSize=9,  textColor=GREY,  alignment=TA_CENTER),
    }


# ── Page template (header / footer) ──────────────────────────────────────────

class _AuditDoc(SimpleDocTemplate):
    """SimpleDocTemplate with a running header/footer on every non-cover page."""

    def __init__(self, path: str, run_id: str, org: str, **kw):
        super().__init__(path, **kw)
        self.run_id = run_id
        self.org    = org

    def handle_pageBegin(self):
        super().handle_pageBegin()
        c   = self.canv
        pn  = c.getPageNumber()
        if pn == 1:
            return   # cover page – no header/footer

        # Header line
        c.saveState()
        c.setStrokeColor(BLUE)
        c.setLineWidth(0.5)
        c.line(L_MARGIN, PAGE_H - T_MARGIN + 10, PAGE_W - R_MARGIN, PAGE_H - T_MARGIN + 10)
        c.setFont("Helvetica", 8)
        c.setFillColor(GREY)
        c.drawString(L_MARGIN, PAGE_H - T_MARGIN + 14,
                     f"IamWatching Security Audit Report  |  {self.org}")
        c.drawRightString(PAGE_W - R_MARGIN, PAGE_H - T_MARGIN + 14,
                          f"Run ID: {self.run_id}")

        # Footer line
        c.setStrokeColor(BLUE)
        c.line(L_MARGIN, B_MARGIN - 10, PAGE_W - R_MARGIN, B_MARGIN - 10)
        c.setFillColor(GREY)
        c.drawString(L_MARGIN, B_MARGIN - 22, "CONFIDENTIAL — Internal Use Only")
        c.drawCentredString(PAGE_W / 2, B_MARGIN - 22, f"Page {pn}")
        c.drawRightString(PAGE_W - R_MARGIN, B_MARGIN - 22,
                          f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d')}")
        c.restoreState()


# ── Section builders ──────────────────────────────────────────────────────────

def _cover(report: dict, styles: dict) -> list:
    org  = report.get("org", "Aniza Corp")
    date = datetime.now(timezone.utc).strftime("%B %d, %Y — %H:%M UTC")
    clouds = ", ".join(report.get("scan_results", {}).keys()).upper() or "N/A"

    elems: list = []
    elems.append(Spacer(1, 1.8 * inch))
    elems.append(Paragraph(_safe(org.upper()), styles["cover_org"]))
    elems.append(Spacer(1, 0.15 * inch))
    elems.append(Paragraph("IamWatching", styles["cover_title"]))
    elems.append(Paragraph("Multi-Cloud IAM Security Audit Report", styles["cover_sub"]))
    elems.append(Spacer(1, 0.3 * inch))
    elems.append(HRFlowable(width=CONTENT_W, thickness=2, color=NAVY))
    elems.append(Spacer(1, 0.2 * inch))
    elems.append(Paragraph(f"Clouds Scanned: {_safe(clouds)}", styles["cover_date"]))
    elems.append(Paragraph(f"Report Date: {date}", styles["cover_date"]))
    elems.append(Paragraph(f"Report Version: v1.3.0", styles["cover_date"]))
    elems.append(Spacer(1, 2.5 * inch))

    # Severity summary boxes
    finding_counts: dict[str, int] = {}
    for f in report.get("findings", []):
        sv = _sev(f)
        finding_counts[sv] = finding_counts.get(sv, 0) + 1
    ne_count = sum(1 for f in report.get("findings", []) if f.get("not_evaluated"))

    box_data = []
    hdr_row  = []
    cnt_row  = []
    lbl_row  = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        n = finding_counts.get(sev, 0)
        bg = SEVERITY_BG[sev]
        hdr_row.append("")
        cnt_row.append(Paragraph(str(n), styles["exec_num"]))
        lbl_row.append(Paragraph(sev, styles["exec_label"]))

    if ne_count:
        hdr_row.append("")
        cnt_row.append(Paragraph(str(ne_count), ParagraphStyle("ne_num", fontSize=24,
            textColor=GREY, fontName="Helvetica-Bold", alignment=TA_CENTER, leading=28)))
        lbl_row.append(Paragraph("NOT EVAL.", styles["exec_label"]))

    cols = len(cnt_row)
    col_w = CONTENT_W / cols
    tbl = Table([cnt_row, lbl_row], colWidths=[col_w] * cols,
                rowHeights=[0.55 * inch, 0.25 * inch])
    tstyle = [
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",  (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING",(0,0), (-1, -1), 4),
        ("BACKGROUND",  (0, 0), (-1, -1), LGREY),
        ("BOX",         (0, 0), (-1, -1), 0.5, GREY),
    ]
    for i, sev in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW"][:cols]):
        tstyle.append(("BACKGROUND", (i, 0), (i, -1), SEVERITY_BG.get(sev, LGREY)))
    tbl.setStyle(TableStyle(tstyle))
    elems.append(tbl)
    elems.append(PageBreak())
    return elems


def _exec_summary(report: dict, styles: dict) -> list:
    elems: list = []
    elems.append(Paragraph("Executive Summary", styles["h1"]))
    elems.append(HRFlowable(width=CONTENT_W, thickness=1, color=BLUE))
    elems.append(Spacer(1, 0.1 * inch))

    scan_results   = report.get("scan_results", {})
    findings       = report.get("findings", [])
    verified_creds = sum(1 for v in report.get("verification_results", []) if v.get("verified_link"))

    evaluated     = [f for f in findings if not f.get("not_evaluated")]
    not_evaluated = [f for f in findings if f.get("not_evaluated")]

    finding_counts: dict[str, int] = {}
    for f in evaluated:
        sv = _sev(f)
        finding_counts[sv] = finding_counts.get(sv, 0) + 1

    # Stats table
    total_principals = sum(
        sr.get("principals", 0) if isinstance(sr, dict) else 0
        for sr in scan_results.values()
    )
    total_resources = sum(
        sr.get("resources", 0) if isinstance(sr, dict) else 0
        for sr in scan_results.values()
    )

    rows = [
        [Paragraph("Metric", styles["tbl_hdr"]), Paragraph("Value", styles["tbl_hdr"])],
        ["Clouds scanned",                        ", ".join(scan_results.keys()).upper() or "None"],
        ["Total principals found",                str(total_principals)],
        ["Total resources scanned",               str(total_resources)],
        ["Verified cross-cloud credentials",      str(verified_creds)],
        ["Total security findings",               str(len(evaluated))],
        ["CRITICAL findings",                     str(finding_counts.get("CRITICAL", 0))],
        ["HIGH findings",                         str(finding_counts.get("HIGH", 0))],
        ["MEDIUM findings",                       str(finding_counts.get("MEDIUM", 0))],
        ["LOW findings",                          str(finding_counts.get("LOW", 0))],
        ["Checks not yet evaluated",              str(len(not_evaluated))],
    ]

    cw = [CONTENT_W * 0.55, CONTENT_W * 0.45]
    tbl = Table(rows, colWidths=cw)
    tstyle = TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR",    (0, 0), (-1, 0), WHITE),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, 0), 10),
        ("FONTSIZE",     (0, 1), (-1, -1), 9),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, LGREY]),
        ("GRID",         (0, 0), (-1, -1), 0.3, GREY),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        # Highlight CRITICAL row red
    ])
    # Colour-code finding rows
    sev_row_map = {
        "CRITICAL findings": RED,
        "HIGH findings": AMBER,
    }
    for i, row in enumerate(rows[1:], 1):
        label = row[0] if isinstance(row[0], str) else ""
        if label in sev_row_map:
            tbl.setStyle(TableStyle([
                ("TEXTCOLOR", (1, i), (1, i), sev_row_map[label]),
                ("FONTNAME",  (1, i), (1, i), "Helvetica-Bold"),
            ]))
    tbl.setStyle(tstyle)
    elems.append(tbl)
    elems.append(Spacer(1, 0.2 * inch))

    if verified_creds > 0:
        msg = (
            f"<b>CRITICAL:</b> {verified_creds} cross-cloud credential leak(s) were VERIFIED as "
            "still-active. These credentials were found embedded in one cloud's compute resources "
            "and confirmed valid in another cloud. Immediate credential rotation is required."
        )
        elems.append(Paragraph(msg, ParagraphStyle("warn_body", fontSize=10,
            textColor=RED, backColor=LRED, borderPadding=8, spaceBefore=4, spaceAfter=4,
            borderColor=RED, borderWidth=1, leading=14)))

    return elems


def _findings_section(findings: list, styles: dict) -> list:
    evaluated     = [f for f in findings if not f.get("not_evaluated")]
    not_evaluated = [f for f in findings if f.get("not_evaluated")]

    elems: list = []
    elems.append(PageBreak())
    elems.append(Paragraph("Security Findings", styles["h1"]))
    elems.append(HRFlowable(width=CONTENT_W, thickness=1, color=BLUE))
    elems.append(Spacer(1, 0.1 * inch))

    if not evaluated:
        elems.append(Paragraph("No findings matched. The environment is clean or the graph is empty.", styles["body"]))
    else:
        # Sort: CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO
        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        evaluated.sort(key=lambda f: sev_order.index(_sev(f)) if _sev(f) in sev_order else 99)

        for finding in evaluated:
            elems.extend(_finding_card(finding, styles))

    # Not-evaluated section
    if not_evaluated:
        elems.append(Spacer(1, 0.2 * inch))
        elems.append(Paragraph("Checks Not Yet Evaluated", styles["h2"]))
        elems.append(Paragraph(
            "The following checks ran successfully but returned no data because the required "
            "graph relationships have not yet been populated. This does NOT mean the environment "
            "is clean — it means additional scan data (resource policies, cross-account trusts) "
            "is needed. Re-run with --import-graph after a full scan to evaluate these checks.",
            styles["body"]))
        elems.append(Spacer(1, 0.1 * inch))
        elems.extend(_not_evaluated_table(not_evaluated, styles))

    return elems


def _finding_card(finding: dict, styles: dict) -> list:
    """Render one finding as a self-contained card that stays together on a page."""
    sev    = _sev(finding)
    bg     = SEVERITY_BG.get(sev, LGREY)
    fg     = SEVERITY_FG.get(sev, BLACK)
    title  = _safe(finding.get("title", "Untitled"), 100)
    rid    = _safe(finding.get("rule_id", ""), 30)
    desc   = _safe(finding.get("description", ""), 600)
    rec    = _safe(finding.get("recommendation", ""), 400)
    mitre  = ", ".join(_safe(m, 60) for m in finding.get("mitre_attack", [])[:3])
    count  = finding.get("affected_count", 0)
    records = finding.get("records", [])[:5]

    # Header bar: severity badge + rule ID + title
    hdr_data = [[
        Paragraph(sev, ParagraphStyle("sev", fontSize=9, fontName="Helvetica-Bold",
                                      textColor=WHITE, alignment=TA_CENTER)),
        Paragraph(f"<b>{rid}</b>  {title}", ParagraphStyle("ftitle", fontSize=10,
                                      textColor=WHITE, fontName="Helvetica-Bold", leading=13)),
    ]]
    hdr_tbl = Table(hdr_data, colWidths=[0.85 * inch, CONTENT_W - 0.85 * inch])
    hdr_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), fg),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))

    body_elems: list = [hdr_tbl]

    # Body panel
    body_rows = []
    if desc:
        body_rows.append([Paragraph("Description", styles["label"]),
                          Paragraph(desc, styles["body"])])
    if rec:
        body_rows.append([Paragraph("Recommendation", styles["label"]),
                          Paragraph(rec, styles["rec"])])
    body_rows.append([Paragraph("Affected", styles["label"]),
                      Paragraph(str(count), styles["body"])])
    if mitre:
        body_rows.append([Paragraph("MITRE ATT&CK", styles["label"]),
                          Paragraph(_safe(mitre, 120), styles["small"])])

    body_tbl = Table(body_rows, colWidths=[1.1 * inch, CONTENT_W - 1.1 * inch])
    body_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",(0, 0), (-1, -1), 7),
        ("RIGHTPADDING",(0,0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0,0),(-1, -1), 4),
        ("GRID",       (0, 0), (-1, -1), 0.2, GREY),
    ]))
    body_elems.append(body_tbl)

    # Affected node samples
    if records:
        body_elems.append(_records_table(records, styles))

    body_elems.append(Spacer(1, 0.15 * inch))

    return [KeepTogether(body_elems[:3]), *body_elems[3:]]


def _records_table(records: list, styles: dict) -> object:
    """
    Render affected resources in a fixed 5-column table:
      Name | Type | Region | Resource ARN/ID | Console URL

    Every record is normalised through _extract_identity() so the table
    looks consistent regardless of which column names the Cypher query used.
    Column widths are fixed fractions of CONTENT_W (7.0") that sum exactly.
    """
    if not records:
        return Spacer(1, 0)

    # Fixed column widths — must sum to CONTENT_W = 7.0 inches
    CW = [1.30 * inch,   # Name / short label
          0.90 * inch,   # Type
          0.70 * inch,   # Region
          2.20 * inch,   # Full ARN / resource ID
          1.90 * inch]   # Console URL
    assert abs(sum(CW) - CONTENT_W) < 0.02, f"Column widths sum {sum(CW):.3f} != {CONTENT_W:.3f}"

    rows = [[
        Paragraph("Resource Name", styles["tbl_hdr"]),
        Paragraph("Type", styles["tbl_hdr"]),
        Paragraph("Region", styles["tbl_hdr"]),
        Paragraph("Resource ARN / ID", styles["tbl_hdr"]),
        Paragraph("Console URL", styles["tbl_hdr"]),
    ]]

    for rec in records:
        if not isinstance(rec, dict):
            continue
        # Skip pure-aggregate rows (only counts, no resource identity)
        ident = _extract_identity(rec)
        if not ident["arn"] and not ident["name"]:
            # Try to show at least the issue text as a single-span note
            issue_text = ident["issue"] or str(rec)
            rows.append([
                Paragraph(_safe(issue_text, 120), styles["tbl_cell"]),
                Paragraph("", styles["tbl_cell"]),
                Paragraph("", styles["tbl_cell"]),
                Paragraph("", styles["tbl_cell"]),
                Paragraph("", styles["tbl_cell"]),
            ])
            continue

        # Name cell: resource name + issue note on second line
        name_text = _safe(ident["name"], 30) or _safe(ident["arn"].split("/")[-1].split(":")[-1], 30)
        if ident["issue"]:
            name_text = name_text + "\n" + _safe(ident["issue"], 45)

        # ARN cell: wrap at natural boundaries (:, /) to fill the 2.2" column
        # ~38 chars per line at 7pt Courier in 2.2"
        arn_text = _wrap_arn(ident["arn"], width=38)

        # URL cell: wrap at / boundaries to fill 1.9"
        url_text = _wrap_arn(ident["url"], width=32)

        rows.append([
            Paragraph(_safe(name_text), styles["tbl_cell"]),
            Paragraph(_safe(ident["rtype"], 20), styles["tbl_cell"]),
            Paragraph(_safe(ident["region"], 15), styles["tbl_cell"]),
            Paragraph(_safe(arn_text), styles["tbl_arn"]),
            Paragraph(_safe(url_text) if ident["url"] else "(see ARN)", styles["tbl_url"]),
        ])

    if len(rows) == 1:   # header only — no data rows
        return Spacer(1, 0)

    tbl = Table(rows, colWidths=CW, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), DGREY),
        ("TEXTCOLOR",     (0, 0), (-1, 0), WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 8),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, LGREY]),
        ("GRID",          (0, 0), (-1, -1), 0.2, GREY),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    return tbl


def _not_evaluated_table(findings: list, styles: dict) -> list:
    rows = [[
        Paragraph("Check ID", styles["tbl_hdr"]),
        Paragraph("Severity", styles["tbl_hdr"]),
        Paragraph("Title", styles["tbl_hdr"]),
        Paragraph("Reason Not Evaluated", styles["tbl_hdr"]),
    ]]
    for f in findings:
        sev    = _sev(f)
        reason = _safe(f.get("not_evaluated_reason", "Missing graph data"), 120)
        rows.append([
            Paragraph(_safe(f.get("rule_id", ""), 20), styles["tbl_arn"]),
            Paragraph(sev, ParagraphStyle("ne_sev", fontSize=8,
                                          textColor=SEVERITY_FG.get(sev, GREY),
                                          fontName="Helvetica-Bold")),
            Paragraph(_safe(f.get("title", ""), 60), styles["ne_cell"]),
            Paragraph(reason, styles["ne_cell"]),
        ])

    cw = [1.4 * inch, 0.7 * inch, 2.2 * inch, CONTENT_W - 4.3 * inch]
    tbl = Table(rows, colWidths=cw, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), DGREY),
        ("TEXTCOLOR",     (0, 0), (-1, 0), WHITE),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, LGREY]),
        ("GRID",          (0, 0), (-1, -1), 0.2, GREY),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    return [tbl, Spacer(1, 0.1 * inch)]


def _appendix(report: dict, styles: dict) -> list:
    elems: list = [PageBreak()]
    elems.append(Paragraph("Appendix — Scan Details", styles["h1"]))
    elems.append(HRFlowable(width=CONTENT_W, thickness=1, color=BLUE))
    elems.append(Spacer(1, 0.1 * inch))

    # Per-cloud stats
    for cloud, data in report.get("scan_results", {}).items():
        if not isinstance(data, dict):
            continue
        elems.append(Paragraph(_safe(cloud.upper()), styles["h2"]))
        rows = []
        for k, v in data.items():
            rows.append([_safe(str(k), 30), _safe(str(v), 80)])
        if rows:
            tbl = Table(rows, colWidths=[CONTENT_W * 0.4, CONTENT_W * 0.6])
            tbl.setStyle(TableStyle([
                ("FONTSIZE",     (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS",(0,0), (-1, -1), [WHITE, LGREY]),
                ("GRID",         (0, 0), (-1, -1), 0.2, GREY),
                ("LEFTPADDING",  (0, 0), (-1, -1), 6),
                ("TOPPADDING",   (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
                ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ]))
            elems.append(tbl)
            elems.append(Spacer(1, 0.1 * inch))

    # Framework coverage
    all_findings = report.get("findings", [])
    by_framework: dict[str, int] = {}
    for f in all_findings:
        fw = _safe(f.get("rule_id", "UNKNOWN").split("-")[0], 30)
        by_framework[fw] = by_framework.get(fw, 0) + 1

    if by_framework:
        elems.append(Paragraph("Checks by Framework", styles["h2"]))
        fw_rows = [[Paragraph("Framework", styles["tbl_hdr"]),
                    Paragraph("Findings", styles["tbl_hdr"])]]
        for fw, cnt in sorted(by_framework.items(), key=lambda x: -x[1]):
            fw_rows.append([_safe(fw, 30), str(cnt)])
        tbl = Table(fw_rows, colWidths=[CONTENT_W * 0.7, CONTENT_W * 0.3])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR",    (0, 0), (-1, 0), WHITE),
            ("FONTSIZE",     (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS",(0,1), (-1, -1), [WHITE, LGREY]),
            ("GRID",         (0, 0), (-1, -1), 0.3, GREY),
            ("LEFTPADDING",  (0, 0), (-1, -1), 8),
            ("TOPPADDING",   (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
            ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ]))
        elems.append(tbl)

    return elems


# ── Public API ────────────────────────────────────────────────────────────────

def generate_pdf_report(
    report: dict,
    output_path: str,
    org: str = "Aniza Corp",
) -> str:
    """
    Generate a clean PDF report from an IamWatching audit report dict.

    Args:
        report:      The report dict from _run_audit (findings, scan_results, etc.)
        output_path: Where to write the PDF (e.g. 'report.pdf')
        org:         Organisation name shown in header/cover

    Returns:
        Absolute path of the written PDF.
    """
    run_id = report.get("run_id", datetime.now().strftime("%Y%m%d-%H%M"))
    styles = _make_styles()

    doc = _AuditDoc(
        output_path,
        run_id=str(run_id)[:20],
        org=_safe(org, 60),
        pagesize=letter,
        leftMargin=L_MARGIN,
        rightMargin=R_MARGIN,
        topMargin=T_MARGIN + 0.2 * inch,   # extra space for header
        bottomMargin=B_MARGIN + 0.25 * inch,
    )

    # Enrich findings dict with not_evaluated flag if it came from serialised JSON
    findings = report.get("findings", [])
    for f in findings:
        if "not_evaluated" not in f:
            f["not_evaluated"] = False

    story: list = []
    story.extend(_cover(report, styles))
    story.extend(_exec_summary(report, styles))
    story.extend(_findings_section(findings, styles))
    story.extend(_appendix(report, styles))

    doc.build(story)
    return str(Path(output_path).resolve())
