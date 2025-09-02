# services/report.py
from typing import Dict, Any, List
from datetime import datetime
import logging
import io

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm

from . import storage


def _draw_multiline(c: canvas.Canvas, text: str, x: float, y: float,
                    max_width: float, leading: float = 14) -> float:
    lines: List[str] = []
    for paragraph in (text or "").split("\n"):
        words = paragraph.split(" ")
        line = ""
        for w in words:
            test = (line + " " + w).strip()
            if c.stringWidth(test) <= max_width:
                line = test
            else:
                if line:
                    lines.append(line)
                line = w
        if line:
            lines.append(line)
    for ln in lines:
        c.drawString(x, y, ln)
        y -= leading
    return y


def recommendations(bundle: Dict[str, Any]) -> List[Dict[str, str]]:
    ti_results = bundle.get("ti_results", [])
    anomalies = bundle.get("anomalies", {}).get("anomalies", [])
    recs: List[Dict[str, str]] = []

    # any provider hit?
    if any(
        prov.get("hit")
        for res in ti_results
        for prov in res.get("providers", {}).values()
    ):
        recs.append({"title": "Block & contain",
                     "action": "Add malicious IPs/domains/hashes to blocklists (firewall, proxy/DNS, EDR)."})
        recs.append({"title": "Hunt & notify",
                     "action": "Create SIEM watchlists for flagged IoCs and alert on new matches."})

    if anomalies:
        recs.append({"title": "Investigate spikes",
                     "action": "Review sources with z-score ≥ 3 for misconfigurations or brute-force attempts."})

    recs.append({"title": "MFA & hardening",
                 "action": "Enforce MFA; tighten conditional access and lockout thresholds."})
    recs.append({"title": "Patch & EDR",
                 "action": "Ensure latest patches and EDR coverage on affected endpoints."})
    return recs


def generate_pdf_and_upload(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a short PDF summary in-memory and upload it to blob storage as 'reports/<instance_id>.pdf'.
    Returns: {"blob_path": "...", "download_url": "/api/report/<instance_id>"}
    """
    instance_id: str = bundle.get("instance_id", "run")
    eda = bundle.get("eda", {}) or {}
    anomalies = bundle.get("anomalies", {}) or {}
    ti_results = bundle.get("ti_results", []) or []
    recs = bundle.get("recommendations", []) or []

    logging.info(f"[REPORT] start generate_pdf_and_upload instance_id={instance_id}")

    # --- build PDF in-memory (A4) ---
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4
    margin = 2 * cm
    x = margin
    y = height - margin

    c.setTitle(f"CyberJoule Report {instance_id}")
    c.setFont("Helvetica-Bold", 16)
    c.drawString(x, y, "AI Data Analysis Agent - Findings Report")
    y -= 20
    c.setFont("Helvetica", 10)
    c.drawString(x, y, f"Run ID: {instance_id}   Generated: {datetime.utcnow().isoformat()}Z")
    y -= 30

    # 1. EDA
    c.setFont("Helvetica-Bold", 12); c.drawString(x, y, "1. Exploratory Analysis"); y -= 16
    c.setFont("Helvetica", 10)
    y = _draw_multiline(c, f"Total events: {eda.get('total_events', 0)}", x, y, width - 2*margin)
    tr = eda.get("time_range")
    if tr:
        y = _draw_multiline(c, f"Time range: {tr.get('start')}  →  {tr.get('end')}", x, y, width - 2*margin)
    y -= 6

    # 2. TI summary
    c.setFont("Helvetica-Bold", 12); c.drawString(x, y, "2. Threat Intelligence Summary"); y -= 16
    c.setFont("Helvetica", 10)
    ti_hits = [r for r in ti_results if r.get("hit")]
    y = _draw_multiline(c, f"IoCs checked: {len(ti_results)} | Hits: {len(ti_hits)}", x, y, width - 2*margin)
    y -= 6

    # 3. Anomalies
    c.setFont("Helvetica-Bold", 12); c.drawString(x, y, "3. Anomaly Detection"); y -= 16
    c.setFont("Helvetica", 10)
    anoms = anomalies.get("anomalies", [])
    if not anoms:
        y = _draw_multiline(c, "No significant anomalies detected (z ≥ 3).", x, y, width - 2*margin)
    else:
        for a in anoms[:20]:
            y = _draw_multiline(
                c,
                f"- {a.get('day')}  src_ip={a.get('key', {}).get('src_ip')}  "
                f"event={a.get('key', {}).get('event_type')}  "
                f"count={a.get('count')}  z={a.get('z')}",
                x, y, width - 2*margin
            )
            if y < margin + 100:
                c.showPage(); y = height - margin; c.setFont("Helvetica", 10)
    y -= 6

    # 4. Recommendations
    c.setFont("Helvetica-Bold", 12); c.drawString(x, y, "4. Recommendations"); y -= 16
    c.setFont("Helvetica", 10)
    for r in recs:
        y = _draw_multiline(c, f"• {r.get('title')}: {r.get('action')}", x, y, width - 2*margin)
        if y < margin + 100:
            c.showPage(); y = height - margin; c.setFont("Helvetica", 10)

    c.showPage()
    c.save()
    pdf_bytes = buf.getvalue()
    logging.info(f"[REPORT] pdf generated bytes={len(pdf_bytes)}")

    # --- upload via storage helper (instance_id, bytes) ---
    try:
        blob_path = storage.upload_report(instance_id, pdf_bytes)
        logging.info(f"[REPORT] uploaded blob_path={blob_path}")
    except Exception as e:
        logging.exception(f"[REPORT] upload failed for {instance_id}: {e}")
        raise

    return {"blob_path": blob_path, "download_url": f"/api/report/{instance_id}"}
