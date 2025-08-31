from typing import Dict, Any, List
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm

from . import storage

def _draw_multiline(c: canvas.Canvas, text: str, x: float, y: float, max_width: float, leading: float = 14):
    lines: List[str] = []
    for paragraph in text.split("\n"):
        words = paragraph.split(" ")
        line = ""
        for w in words:
            test = (line + " " + w).strip()
            if c.stringWidth(test) <= max_width:
                line = test
            else:
                lines.append(line)
                line = w
        if line:
            lines.append(line)
    for line in lines:
        c.drawString(x, y, line)
        y -= leading
    return y

def recommendations(bundle: Dict[str, Any]) -> List[Dict[str, str]]:
    ti_results = bundle.get("ti_results", [])
    anomalies = bundle.get("anomalies", {}).get("anomalies", [])

    recs: List[Dict[str, str]] = []

    if any((prov.get("hit") for res in ti_results for prov in res.get("providers", {}).values())):
        recs.append({"title": "Block & contain", "action": "Add malicious IPs/domains/hashes to blocklists (firewall, proxy/DNS, EDR)."})
        recs.append({"title": "Hunt & notify", "action": "Create SIEM watchlists for flagged IoCs and alert on new matches."})

    if anomalies:
        recs.append({"title": "Investigate spikes", "action": "Review sources with z-score ≥ 3 for misconfigurations or brute-force attempts."})

    recs.append({"title": "MFA & hardening", "action": "Enforce MFA; tighten conditional access and lockout thresholds."})
    recs.append({"title": "Patch & EDR", "action": "Ensure latest patches and EDR coverage on affected endpoints."})

    return recs

def generate_pdf_and_upload(bundle: Dict[str, Any]) -> Dict[str, Any]:
    instance_id: str = bundle.get("instance_id", "run")
    eda = bundle.get("eda", {})
    anomalies = bundle.get("anomalies", {})
    ti_results = bundle.get("ti_results", [])
    recs = bundle.get("recommendations", [])

    file_name = f"analysis-{instance_id}.pdf"
    tmp_path = f"/tmp/{file_name}"

    c = canvas.Canvas(tmp_path, pagesize=A4)
    width, height = A4
    margin = 2 * cm
    x = margin
    y = height - margin

    c.setFont("Helvetica-Bold", 16)
    c.drawString(x, y, "AI Data Analysis Agent - Findings Report")
    y -= 20
    c.setFont("Helvetica", 10)
    c.drawString(x, y, f"Run ID: {instance_id}   Generated: {datetime.utcnow().isoformat()}Z")
    y -= 30

    c.setFont("Helvetica-Bold", 12); c.drawString(x, y, "1. Exploratory Analysis"); y -= 16
    c.setFont("Helvetica", 10)
    y = _draw_multiline(c, f"Total events: {eda.get('total_events', 0)}", x, y, width - 2*margin)
    tr = eda.get("time_range")
    if tr:
        y = _draw_multiline(c, f"Time range: {tr.get('start')}  →  {tr.get('end')}", x, y, width - 2*margin)
    y -= 6

    c.setFont("Helvetica-Bold", 12); c.drawString(x, y, "2. Threat Intelligence Summary"); y -= 16
    c.setFont("Helvetica", 10)
    ti_hits = [r for r in ti_results if r.get("hit")]
    y = _draw_multiline(c, f"IoCs checked: {len(ti_results)} | Hits: {len(ti_hits)}", x, y, width - 2*margin)
    y -= 6

    c.setFont("Helvetica-Bold", 12); c.drawString(x, y, "3. Anomaly Detection"); y -= 16
    c.setFont("Helvetica", 10)
    anoms = anomalies.get("anomalies", [])
    if not anoms:
        y = _draw_multiline(c, "No significant anomalies detected (z >= 3).", x, y, width - 2*margin)
    else:
        for a in anoms[:20]:
            y = _draw_multiline(c, f"- {a['day']} src_ip={a['key']['src_ip']} event={a['key']['event_type']} count={a['count']} z={a['z']}", x, y, width - 2*margin)
            if y < margin + 100:
                c.showPage(); y = height - margin; c.setFont("Helvetica", 10)
    y -= 6

    c.setFont("Helvetica-Bold", 12); c.drawString(x, y, "4. Recommendations"); y -= 16
    c.setFont("Helvetica", 10)
    for r in recs:
        y = _draw_multiline(c, f"• {r['title']}: {r['action']}", x, y, width - 2*margin)
        if y < margin + 100:
            c.showPage(); y = height - margin; c.setFont("Helvetica", 10)

    c.showPage(); c.save()

    blob_path = storage.upload_report(tmp_path, instance_id)
    return {"blob_path": blob_path, "download_url": f"/api/report/{instance_id}"}
