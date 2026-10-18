"""JSON & HTML reports; only summarized evidence, never raw device config."""
from datetime import datetime, timezone
from pathlib import Path
import json

from jinja2 import Environment, FileSystemLoader, select_autoescape


def summary(results):
    counts = {k: sum(x["status"] == k for x in results)
              for k in ("PASS", "FAIL", "REVIEW", "ERROR", "N/A")}
    evaluated = counts["PASS"] + counts["FAIL"]
    return {"total": len(results), "evaluated": evaluated,
            "coverage_percent": round(evaluated / len(results) * 100, 2) if results else 0,
            "compliance_percent": round(counts["PASS"] / evaluated * 100, 2)
            if evaluated else None, **{k.lower(): v for k, v in counts.items()}}


def make_report(host, username, results, mode="READ_ONLY_AUDIT", metadata=None):
    return {
        "tool": "CIS Palo Alto Security Auditor",
        "benchmark": "CIS Palo Alto Firewall 11 v1.2.0 - selected controls",
        "host": host,
        "username": username,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "scope_note": "Only implemented checks; score is NOT full Benchmark compliance.",
        "summary": summary(results),
        "metadata": metadata or {},
        "results": results,
    }


def save(report, out_dir="reports"):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_host = "".join(c if c.isalnum() else "_" for c in report["host"])
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    basename = f"{safe_host}_{stamp}"
    json_path = out_dir / f"{basename}.json"
    html_path = out_dir / f"{basename}.html"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    template_root = Path(__file__).resolve().parent.parent / "templates"
    env = Environment(loader=FileSystemLoader(str(template_root)),
                      autoescape=select_autoescape(["html", "xml"]))
    html = env.get_template("report.html").render(report=report)
    html_path.write_text(html, encoding="utf-8")
    return json_path, html_path
