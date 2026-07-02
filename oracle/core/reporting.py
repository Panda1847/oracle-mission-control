"""
ORACLE — Reporting  (oracle/core/reporting.py)

Generates deliverable HTML reports from the KnowledgeGraph.
Falls back to deterministic narrative when no AI key is present.
"""

from __future__ import annotations

from datetime import datetime, timezone
import html
from typing import Any

try:
    from jinja2 import Template  # type: ignore
except Exception:  # pragma: no cover
    Template = None  # type: ignore


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def deterministic_narrative(graph_dict: dict[str, Any], mission_name: str) -> str:
    hosts = graph_dict.get("hosts") or {}
    findings = graph_dict.get("findings") or []

    lines: list[str] = []
    lines.append(f"Mission '{mission_name}' discovered {len(hosts)} host(s) with {len(findings)} finding(s).")

    # Mention highest-severity findings first.
    rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    findings_sorted = sorted(findings, key=lambda f: rank.get(f.get("severity", "INFO"), 0), reverse=True)
    top = findings_sorted[:5]
    if top:
        lines.append("Key risks observed:")
        for f in top:
            sev = f.get("severity", "INFO")
            title = f.get("title", "")
            host = f.get("host", "")
            port = f.get("port", 0)
            lines.append(f"- [{sev}] {title} ({host}:{port})")

    # Basic attack-path style narrative from ports and CVEs.
    for ip, h in list(hosts.items())[:8]:
        ports = (h.get("ports") or [])[:12]
        if not ports:
            continue
        web = [p for p in ports if (p.get("service") or "").lower() in ("http", "https")]
        ssh = [p for p in ports if (p.get("service") or "").lower() == "ssh"]
        smb = [p for p in ports if (p.get("service") or "").lower() in ("smb", "microsoft-ds", "netbios-ssn")]
        if web:
            p = web[0]
            lines.append(f"ORACLE identified web exposure on {ip}:{p.get('port')}, suitable for enumeration and content discovery.")
        if smb:
            p = smb[0]
            lines.append(f"SMB surface appeared on {ip}:{p.get('port')}, a candidate for share enumeration and auth testing.")
        if ssh:
            p = ssh[0]
            lines.append(f"SSH was reachable on {ip}:{p.get('port')}, which can become a post-compromise foothold if credentials are recovered.")

        # Mention CVEs if present on any port
        for p in ports:
            cves = p.get("cves") or []
            if cves:
                svc = (p.get("service") or "?").upper()
                lines.append(f"Service {svc} on {ip}:{p.get('port')} matched known CVEs: {', '.join(cves[:5])}.")
                break

    return "\n".join(lines)


_HTML_TMPL_SRC = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>ORACLE Report — {{ mission }}</title>
  <style>
    :root{
      --bg0:#070a12;
      --bg1:#0b1220;
      --card:#0e172a;
      --card2:#0b1020;
      --ink:#e6edf7;
      --muted:#96a3b8;
      --border:#24324a;
      --accent:#00ff88;
      --blue:#3b82f6;
      --red:#ff4444;
      --orange:#ff8800;
      --yellow:#ffdd00;
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      background:radial-gradient(1200px 600px at 20% 0%, #132048 0%, transparent 55%),
                 radial-gradient(900px 500px at 80% 10%, #1a2a18 0%, transparent 60%),
                 linear-gradient(180deg, var(--bg0), var(--bg1));
      color:var(--ink);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      line-height:1.45;
    }
    header{
      padding:28px 18px 14px;
      border-bottom:1px solid var(--border);
      background:linear-gradient(180deg, rgba(14,23,42,0.8), rgba(7,10,18,0));
    }
    .wrap{max-width:1060px;margin:0 auto}
    .kicker{color:var(--muted);font-size:12px;letter-spacing:2px;text-transform:uppercase}
    h1{margin:6px 0 8px;font-size:26px;letter-spacing:1px}
    .meta{display:flex;gap:14px;flex-wrap:wrap;color:var(--muted);font-size:12px}
    .pill{border:1px solid var(--border);background:rgba(14,23,42,0.65);padding:6px 10px;border-radius:999px}
    main{padding:18px}
    .grid{display:grid;grid-template-columns:1.25fr 0.75fr;gap:14px}
    @media (max-width: 900px){.grid{grid-template-columns:1fr}}
    .card{border:1px solid var(--border);background:rgba(14,23,42,0.72);border-radius:10px;overflow:hidden}
    .ch{padding:10px 12px;border-bottom:1px solid var(--border);color:var(--muted);font-size:12px;letter-spacing:1px;text-transform:uppercase}
    .cb{padding:12px}
    .narr{white-space:pre-wrap;font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace}
    table{width:100%;border-collapse:collapse;font-size:12px}
    th,td{padding:8px 8px;border-bottom:1px solid rgba(36,50,74,0.6);vertical-align:top}
    th{color:var(--muted);font-weight:600;text-align:left}
    .sev{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;border:1px solid var(--border)}
    .sev.CRITICAL{border-color:rgba(255,68,68,0.6);color:var(--red)}
    .sev.HIGH{border-color:rgba(255,136,0,0.6);color:var(--orange)}
    .sev.MEDIUM{border-color:rgba(255,221,0,0.5);color:var(--yellow)}
    .sev.LOW{border-color:rgba(59,130,246,0.55);color:var(--blue)}
    .sev.INFO{border-color:rgba(150,163,184,0.4);color:var(--muted)}
    .muted{color:var(--muted)}
    .mono{font-family:inherit}
    footer{padding:18px;color:var(--muted);font-size:11px;text-align:center}
  </style>
</head>
<body>
  <header>
    <div class="wrap">
      <div class="kicker">Autonomous Recon Intelligence</div>
      <h1>ORACLE Report: {{ mission }}</h1>
      <div class="meta">
        <div class="pill">Generated: <span class="mono">{{ generated_at }}</span></div>
        <div class="pill">Hosts: <span class="mono">{{ stats.hosts }}</span></div>
        <div class="pill">Findings: <span class="mono">{{ stats.findings }}</span></div>
        <div class="pill">Critical: <span class="mono">{{ stats.critical }}</span></div>
        <div class="pill">High: <span class="mono">{{ stats.high }}</span></div>
      </div>
    </div>
  </header>

  <main class="wrap">
    <div class="grid">
      <section class="card">
        <div class="ch">Tactical Narrative</div>
        <div class="cb narr">{{ narrative }}</div>
      </section>

      <section class="card">
        <div class="ch">Scope Snapshot</div>
        <div class="cb">
          <div class="muted" style="margin-bottom:10px">Discovered Hosts</div>
          <table>
            <thead><tr><th>Host</th><th>Ports / Versions / CVEs</th></tr></thead>
            <tbody>
              {% for ip, host in hosts.items() %}
              <tr>
                <td class="mono">{{ ip }}</td>
                <td class="mono">
                  {% for p in host.ports[:10] %}
                    <div>
                      {{ p.port }}/{{ p.service or "?" }}
                      {% if p.version %} — {{ p.version }}{% endif %}
                      {% if p.cves %} [{{ p.cves[:3] | join(", ") }}]{% endif %}
                      {% if p.cvss %} (CVSS {{ p.cvss }}){% endif %}
                    </div>
                  {% endfor %}
                </td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      </section>
    </div>

    <section class="card" style="margin-top:14px">
      <div class="ch">Findings</div>
      <div class="cb">
        <table>
          <thead><tr><th>Severity</th><th>Title</th><th>Description</th><th>Host</th><th>Port</th></tr></thead>
          <tbody>
          {% for f in findings %}
            <tr>
              <td><span class="sev {{ f.severity }}">{{ f.severity }}</span></td>
              <td>{{ f.title }}</td>
              <td>{{ f.description }}</td>
              <td class="mono">{{ f.host }}</td>
              <td class="mono">{{ f.port }}</td>
            </tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
    </section>

    <section class="card" style="margin-top:14px">
      <div class="ch">Port & CVE Details</div>
      <div class="cb">
        <table>
          <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Version</th><th>CVEs</th><th>CVSS</th></tr></thead>
          <tbody>
          {% for ip, host in hosts.items() %}
            {% for p in host.ports[:30] %}
            <tr>
              <td class="mono">{{ ip }}</td>
              <td class="mono">{{ p.port }}</td>
              <td>{{ p.service or "?" }}</td>
              <td>{{ p.version or "" }}</td>
              <td>{{ p.cves[:8] | join(", ") if p.cves else "" }}</td>
              <td>{{ p.cvss if p.cvss else "" }}</td>
            </tr>
            {% endfor %}
          {% endfor %}
          </tbody>
        </table>
      </div>
    </section>
  </main>

  <footer>ORACLE v3.2 • Intended for authorized lab environments only</footer>
</body>
</html>"""


def render_html_report(*, graph_dict: dict[str, Any], mission_name: str, narrative: str) -> str:
    stats = graph_dict.get("stats") or {}
    hosts = graph_dict.get("hosts") or {}
    findings = graph_dict.get("findings") or []
    if Template is not None:
        tmpl = Template(_HTML_TMPL_SRC)
        return tmpl.render(
            mission=mission_name,
            generated_at=_utc_now(),
            stats=stats,
            hosts=hosts,
            findings=findings,
            narrative=narrative,
        )

    # Minimal fallback without Jinja2 (keeps report generation functional).
    def _stat(k: str) -> str:
        return html.escape(str((stats or {}).get(k, 0)))

    host_lines = []
    for ip, host in list(hosts.items())[:200]:
        ports = (host.get("ports") or [])[:10]
        parts = []
        for p in ports:
            cves = p.get("cves") or []
            cve_text = f" [{', '.join(cves[:3])}]" if cves else ""
            version = f" - {p.get('version')}" if p.get("version") else ""
            parts.append(f"{p.get('port')}/{p.get('service') or '?'}{version}{cve_text}")
        host_lines.append(
            f"<tr><td>{html.escape(str(ip))}</td><td>{html.escape('; '.join(parts))}</td></tr>"
        )

    finding_lines = []
    for f in list(findings)[:500]:
        finding_lines.append(
            "<tr>"
            f"<td>{html.escape(str(f.get('severity', 'INFO')))}</td>"
            f"<td>{html.escape(str(f.get('title','')))}</td>"
            f"<td>{html.escape(str(f.get('description','')))}</td>"
            f"<td>{html.escape(str(f.get('host','')))}</td>"
            f"<td>{html.escape(str(f.get('port',0)))}</td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>ORACLE Report — {html.escape(mission_name)}</title></head>
<body>
<h1>ORACLE Report: {html.escape(mission_name)}</h1>
<p>Generated: {html.escape(_utc_now())}</p>
<p>Hosts: {_stat('hosts')} Findings: {_stat('findings')} Critical: {_stat('critical')} High: {_stat('high')}</p>
<h2>Tactical Narrative</h2>
<pre>{html.escape(narrative)}</pre>
<h2>Scope Snapshot</h2>
<table border="1" cellspacing="0" cellpadding="4"><tr><th>Host</th><th>Ports / Versions / CVEs</th></tr>{''.join(host_lines)}</table>
<h2>Findings</h2>
<table border="1" cellspacing="0" cellpadding="4"><tr><th>Severity</th><th>Title</th><th>Description</th><th>Host</th><th>Port</th></tr>{''.join(finding_lines)}</table>
</body></html>"""
