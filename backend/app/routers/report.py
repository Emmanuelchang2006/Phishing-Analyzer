from __future__ import annotations

import io
from datetime import datetime, timezone
from uuid import UUID

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db_session
from app.repositories.scan_repository import ScanRepository
from app.schemas.scan import ScanResponse

router = APIRouter(prefix="/api/v1", tags=["reports"])


@router.get(
    "/scan/{scan_id}/report",
    summary="Export scan result as a SOC-style PDF report",
    response_class=StreamingResponse,
)
async def export_pdf_report(
    scan_id: UUID,
    db: Optional[AsyncSession] = Depends(get_db_session),
) -> StreamingResponse:
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is not available — PDF export requires scan history.",
        )
    repo = ScanRepository(db)
    record = await repo.get_by_id(scan_id)
    if record is None or record.result_json is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    result = ScanResponse(**record.result_json)
    pdf_bytes = _build_pdf(result)

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="phishing-report-{scan_id}.pdf"',
            "Cache-Control": "no-cache",
        },
    )


# ── PDF builder ───────────────────────────────────────────────────────────────

def _build_pdf(result: ScanResponse) -> bytes:
    from fpdf import FPDF  # imported lazily so missing dep doesn't crash startup

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_margins(15, 15, 15)

    # ── Header bar ────────────────────────────────────────────────────────────
    pdf.set_fill_color(15, 15, 15)
    pdf.rect(0, 0, 210, 32, "F")
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(255, 255, 255)
    pdf.set_y(8)
    pdf.cell(0, 8, "Phishing Analyzer — SOC Incident Report", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(140, 140, 140)
    pdf.cell(0, 5, f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | CONFIDENTIAL", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    pdf.set_text_color(20, 20, 20)

    # ── Risk summary ──────────────────────────────────────────────────────────
    _section(pdf, "Risk Summary")
    if result.risk_score:
        level = result.risk_score.level.upper()
        colors = {"MALICIOUS": (220, 38, 38), "SUSPICIOUS": (245, 158, 11), "CLEAN": (16, 185, 129)}
        r, g, b = colors.get(level, (100, 100, 100))
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(r, g, b)
        pdf.cell(0, 7, f"{level}  —  {result.risk_score.score} / 100", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(20, 20, 20)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, f"Confidence: {result.risk_score.confidence * 100:.0f}%", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)

    _kv(pdf, "Target", result.target[:120])
    _kv(pdf, "Type", result.scan_type.upper())
    _kv(pdf, "Scan ID", str(result.scan_id))
    _kv(pdf, "Scanned At", result.scanned_at.strftime("%Y-%m-%d %H:%M UTC"))
    pdf.ln(3)

    # ── Contributing factors ───────────────────────────────────────────────────
    if result.risk_score and result.risk_score.contributing_factors:
        _section(pdf, "Contributing Factors")
        for f in result.risk_score.contributing_factors:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(20, 20, 20)
            pdf.cell(6, 5, "•")
            pdf.multi_cell(0, 5, f, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    # ── MITRE ATT&CK ──────────────────────────────────────────────────────────
    if result.mitre_tactics and result.mitre_tactics.techniques:
        _section(pdf, "MITRE ATT&CK Mapping")
        for t in result.mitre_tactics.techniques:
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(20, 20, 20)
            pdf.cell(0, 5, f"{t.technique_id}: {t.technique_name}  ({t.tactic})", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(6)
            pdf.multi_cell(0, 4, t.reason, new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(20, 20, 20)
        pdf.ln(2)

    # ── AI Verdict ────────────────────────────────────────────────────────────
    if result.ai_verdict:
        v = result.ai_verdict
        _section(pdf, "AI Verdict")
        _kv(pdf, "Verdict", v.verdict.upper())
        _kv(pdf, "Confidence", f"{v.confidence * 100:.0f}%")
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 5, v.executive_summary, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)
        if v.key_indicators:
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 5, "Key Indicators:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 9)
            for ind in v.key_indicators:
                pdf.cell(6, 5, "•")
                pdf.multi_cell(0, 5, ind, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 5, f"Recommended action: {v.recommended_action}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    # ── Typosquatting ─────────────────────────────────────────────────────────
    if result.typosquatting:
        _section(pdf, "Typosquatting Detection")
        if result.typosquatting.is_typosquatting:
            _kv(pdf, "Status", "DETECTED")
            _kv(pdf, "Checked Domain", result.typosquatting.checked_domain or "—")
            for m in result.typosquatting.matches[:3]:
                pdf.set_font("Helvetica", "", 9)
                pdf.cell(0, 5, f"  Resembles {m.brand} ({m.brand_domain}) — edit distance {m.distance}, {m.similarity:.0%} similar", new_x="LMARGIN", new_y="NEXT")
        else:
            _kv(pdf, "Status", "CLEAN — no brand impersonation detected")
        pdf.ln(2)

    # ── Keywords ──────────────────────────────────────────────────────────────
    if result.keywords and result.keywords.matches:
        _section(pdf, "Phishing Keyword Analysis")
        _kv(pdf, "Total Weight", str(result.keywords.total_weight))
        _kv(pdf, "Categories", ", ".join(result.keywords.categories))
        for kw in result.keywords.matches[:12]:
            pdf.set_font("Helvetica", "", 8)
            pdf.cell(0, 4, f"  [{kw.category}]  \"{kw.keyword}\"  (weight {kw.weight})", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    # ── URL Analysis ──────────────────────────────────────────────────────────
    if result.url_analysis and result.url_analysis.analyzed_urls:
        _section(pdf, "URL Analysis")
        for feat in result.url_analysis.analyzed_urls[:5]:
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(20, 20, 20)
            pdf.cell(0, 4, feat.url[:90], new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(60, 60, 60)
            tags = []
            if feat.entropy:
                tags.append(f"entropy={feat.entropy:.2f}")
            if feat.is_shortener:
                tags.append("shortener")
            if feat.has_credential_keywords:
                tags.append("credential-keywords")
            if feat.has_homograph:
                tags.append("HOMOGRAPH")
            if feat.ml_phishing_score is not None:
                tags.append(f"ML={feat.ml_phishing_score:.0%}")
            if tags:
                pdf.cell(6)
                pdf.cell(0, 4, "  ".join(tags), new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(20, 20, 20)
            pdf.ln(1)
        pdf.ln(1)

    # ── Threat Intelligence ───────────────────────────────────────────────────
    if result.threat_intel:
        _section(pdf, "Threat Intelligence")
        for ti in result.threat_intel:
            pdf.set_font("Helvetica", "B", 9)
            status_str = "DETECTED" if ti.detected else ("ERROR" if ti.error else "CLEAN")
            pdf.cell(0, 5, f"{ti.source.upper()}: {status_str}", new_x="LMARGIN", new_y="NEXT")
            if ti.error:
                pdf.set_font("Helvetica", "I", 8)
                pdf.set_text_color(130, 130, 130)
                pdf.cell(6)
                pdf.cell(0, 4, ti.error[:100], new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(20, 20, 20)
        pdf.ln(2)

    # ── WHOIS ─────────────────────────────────────────────────────────────────
    if result.whois:
        _section(pdf, "WHOIS")
        w = result.whois
        if w.registrar:
            _kv(pdf, "Registrar", w.registrar[:80])
        if w.domain_age_days is not None:
            _kv(pdf, "Domain Age", f"{w.domain_age_days} days")
        if w.creation_date:
            _kv(pdf, "Created", str(w.creation_date)[:10])
        if w.country:
            _kv(pdf, "Country", w.country)
        pdf.ln(2)

    # ── Email Authentication ──────────────────────────────────────────────────
    if result.email_auth:
        _section(pdf, "Email Authentication")
        a = result.email_auth
        _kv(pdf, "SPF", a.spf_status or "—")
        _kv(pdf, "DKIM", a.dkim_status or "—")
        _kv(pdf, "DMARC", a.dmarc_status or "—")
        if a.domain_mismatch:
            _kv(pdf, "Domain Mismatch", f"From: {a.from_domain} | Reply-To: {a.reply_to_domain}")
        pdf.ln(2)

    # ── Email Header Routing ───────────────────────────────────────────────────
    if result.email_headers and result.email_headers.hop_count > 0:
        _section(pdf, "Email Routing Chain")
        eh = result.email_headers
        _kv(pdf, "Hop Count", str(eh.hop_count))
        if eh.originating_ip:
            _kv(pdf, "Originating IP", eh.originating_ip)
        if eh.x_mailer:
            _kv(pdf, "X-Mailer", eh.x_mailer[:80])
        for i, hop in enumerate(eh.hops[:5], 1):
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(60, 60, 60)
            details = f"Hop {i}: from {hop.from_host or '?'} → by {hop.by_host or '?'}"
            if hop.ip:
                details += f" [{hop.ip}]"
            pdf.cell(0, 4, details[:100], new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(20, 20, 20)
        pdf.ln(2)

    # ── Footer ────────────────────────────────────────────────────────────────
    pdf.set_y(-18)
    pdf.set_font("Helvetica", "I", 7)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 5, "Phishing Analyzer | Confidential SOC Report — For authorized security personnel only", align="C", new_x="LMARGIN", new_y="NEXT")

    return bytes(pdf.output())


def _section(pdf, title: str) -> None:
    pdf.set_fill_color(235, 235, 235)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(20, 20, 20)
    pdf.cell(0, 6, f"  {title}", fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)


def _kv(pdf, key: str, value: str) -> None:
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(70, 70, 70)
    pdf.cell(38, 5, f"{key}:", new_x="RIGHT", new_y="TOP")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(20, 20, 20)
    pdf.multi_cell(0, 5, value, new_x="LMARGIN", new_y="NEXT")
