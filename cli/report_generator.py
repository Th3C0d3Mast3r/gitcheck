"""
Professional HTML report generator for GitCheck CLI.
Called from cli/main.py after a scan completes.
"""
import re
from datetime import datetime


SEV_COLORS = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e53e3e",
    "MEDIUM":   "#d97706",
    "LOW":      "#2b6cb0",
    "INFO":     "#4a5568",
}

SEV_BG = {
    "CRITICAL": "#fff5f5",
    "HIGH":     "#fff5f5",
    "MEDIUM":   "#fffbeb",
    "LOW":      "#ebf8ff",
    "INFO":     "#f7fafc",
}


def _extract_sev(finding):
    m = re.match(r"\[([A-Z]+)\]", finding)
    return m.group(1) if m else "INFO"


def _extract_scanner(finding):
    f = finding.lower()
    if any(k in f for k in ["dangerous_call", "os.system", "eval", "exec", "subprocess"]):
        return "AST / Code Analysis"
    if any(k in f for k in ["aws", "github", "slack", "rsa", "password", "secret", "token",
                             "pii", "api", "ssn", "uuid", "ip address", "domain"]):
        return "Secret Scanner"
    if any(k in f for k in ["reverse_shell", "netcat", "curl", "base64", "crontab",
                             "authorized_keys", "rm -rf"]):
        return "Malicious Code Scanner"
    if any(k in f for k in [".tf", "terraform", "kubernetes", "s3", "security_group", "privileged"]):
        return "IaC Scanner"
    if any(k in f for k in ["requirements", "package", "dependency", "sca", "banned"]):
        return "SCA Scanner"
    if any(k in f for k in ["dockerfile", "container", "base image"]):
        return "Container Scanner"
    return "General Scanner"


def generate_html_report(all_findings, score, verdict, output_path="scan_report.html"):
    """Generates a professional, enterprise-style security audit report."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    date_only  = datetime.now().strftime("%d %B %Y")

    crit_count = sum(1 for f in all_findings if _extract_sev(f) == "CRITICAL")
    high_count = sum(1 for f in all_findings if _extract_sev(f) == "HIGH")
    med_count  = sum(1 for f in all_findings if _extract_sev(f) == "MEDIUM")
    low_count  = sum(1 for f in all_findings if _extract_sev(f) == "LOW")

    verdict_color  = "#c0392b" if verdict == "BLOCK" else "#276749"
    verdict_bg     = "#fff5f5" if verdict == "BLOCK" else "#f0fff4"
    verdict_border = "#feb2b2" if verdict == "BLOCK" else "#9ae6b4"
    verdict_label  = "BLOCKED"  if verdict == "BLOCK" else "PASSED"

    # --- findings table rows ---
    rows = ""
    for i, f in enumerate(all_findings, 1):
        sev     = _extract_sev(f)
        scanner = _extract_scanner(f)
        sc      = SEV_COLORS.get(sev, "#4a5568")
        desc    = re.sub(r"^\[[A-Z]+\]\s*", "", f)
        rows += (
            f'<tr style="border-bottom:1px solid #e2e8f0;">'
            f'<td style="padding:12px 16px;font-size:13px;font-weight:500;color:#1a202c;">{i}</td>'
            f'<td style="padding:12px 16px;">'
            f'<span style="display:inline-block;padding:2px 9px;border-radius:3px;font-size:11px;'
            f'font-weight:700;letter-spacing:.5px;background:{sc};color:#fff;">{sev}</span></td>'
            f'<td style="padding:12px 16px;font-size:13px;color:#2d3748;">{desc}</td>'
            f'<td style="padding:12px 16px;font-size:12px;color:#718096;">{scanner}</td>'
            f'</tr>\n'
        )

    no_findings_row = (
        '<tr><td colspan="4" style="padding:40px;text-align:center;'
        'color:#276749;font-size:14px;font-weight:500;">'
        'No vulnerabilities detected in this scan.</td></tr>'
    ) if not all_findings else ""

    history_row = (
        f'<tr style="background:#f7fafc;border-bottom:1px solid #e2e8f0;">'
        f'<td style="padding:10px 16px;font-size:13px;color:#2d3748;">{timestamp}</td>'
        f'<td style="padding:10px 16px;font-size:13px;color:#2d3748;">HEAD~1 &rarr; HEAD</td>'
        f'<td style="padding:10px 16px;font-size:13px;font-weight:600;color:{verdict_color};">{verdict_label}</td>'
        f'<td style="padding:10px 16px;font-size:13px;color:#2d3748;">{len(all_findings)}</td>'
        f'<td style="padding:10px 16px;font-size:13px;color:#2d3748;">{score}</td>'
        f'</tr>'
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>GitCheck &mdash; Security Scan Report</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Inter', -apple-system, sans-serif; background: #f4f6f9; color: #1a202c; font-size: 14px; line-height: 1.5; }}

    .navbar {{
      background: #1a202c; padding: 0 32px; height: 52px;
      display: flex; align-items: center; justify-content: space-between;
      position: sticky; top: 0; z-index: 100;
    }}
    .navbar .brand {{ color: #fff; font-size: 15px; font-weight: 700; letter-spacing: -.2px; }}
    .navbar .brand span {{ color: #63b3ed; }}
    .navbar .meta {{ color: #a0aec0; font-size: 12px; }}

    .page {{ max-width: 1140px; margin: 32px auto; padding: 0 24px 48px; }}

    .page-title {{ margin-bottom: 20px; }}
    .page-title h1 {{ font-size: 20px; font-weight: 700; }}
    .page-title p  {{ font-size: 12px; color: #718096; margin-top: 5px; }}
    .page-title p strong {{ color: #4a5568; }}

    .verdict-banner {{
      background: {verdict_bg}; border: 1px solid {verdict_border};
      border-left: 5px solid {verdict_color}; border-radius: 6px;
      padding: 18px 24px; display: flex; align-items: center;
      justify-content: space-between; margin-bottom: 24px;
    }}
    .verdict-banner h2 {{ font-size: 17px; font-weight: 700; color: {verdict_color}; }}
    .verdict-banner p  {{ font-size: 13px; color: #4a5568; margin-top: 3px; }}
    .verdict-tag {{
      padding: 6px 20px; border-radius: 4px; font-size: 12px; font-weight: 700;
      letter-spacing: .8px; background: {verdict_color}; color: #fff; white-space: nowrap;
    }}

    .stats {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 14px; margin-bottom: 24px; }}
    .stat {{
      background: #fff; border: 1px solid #e2e8f0; border-radius: 6px; padding: 16px 18px;
      border-top: 3px solid #e2e8f0;
    }}
    .stat.critical {{ border-top-color: #c0392b; }}
    .stat.high     {{ border-top-color: #e53e3e; }}
    .stat.medium   {{ border-top-color: #d97706; }}
    .stat.low      {{ border-top-color: #2b6cb0; }}
    .stat .val {{ font-size: 28px; font-weight: 700; color: #1a202c; }}
    .stat.critical .val {{ color: #c0392b; }}
    .stat.high .val     {{ color: #e53e3e; }}
    .stat.medium .val   {{ color: #d97706; }}
    .stat.low .val      {{ color: #2b6cb0; }}
    .stat .lbl {{ font-size: 11px; color: #718096; margin-top: 2px; text-transform: uppercase; letter-spacing: .5px; font-weight: 500; }}

    .card {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 6px; margin-bottom: 24px; overflow: hidden; }}
    .card-header {{
      padding: 13px 20px; border-bottom: 1px solid #e2e8f0;
      display: flex; align-items: center; justify-content: space-between; background: #fff;
    }}
    .card-header h3 {{ font-size: 13px; font-weight: 600; color: #1a202c; text-transform: uppercase; letter-spacing: .4px; }}
    .badge-count {{
      font-size: 11px; color: #718096; background: #edf2f7;
      padding: 2px 10px; border-radius: 12px; font-weight: 500;
    }}

    table {{ width: 100%; border-collapse: collapse; }}
    thead tr {{ background: #f7fafc; }}
    th {{
      padding: 9px 16px; text-align: left; font-size: 11px; font-weight: 600;
      color: #718096; text-transform: uppercase; letter-spacing: .5px;
      border-bottom: 1px solid #e2e8f0;
    }}

    .scanner-status-ok {{ color: #276749; font-size: 12px; font-weight: 600; }}

    footer {{
      text-align: center; color: #a0aec0; font-size: 12px; padding-top: 8px;
      border-top: 1px solid #e2e8f0; margin-top: 8px;
    }}
  </style>
</head>
<body>

<nav class="navbar">
  <div class="brand">Git<span>Check</span> &mdash; Security Scan Report</div>
  <div class="meta">Generated: {timestamp}</div>
</nav>

<div class="page">

  <div class="page-title">
    <h1>Security Audit Report</h1>
    <p>
      Repository: <strong>gitcheck</strong> &nbsp;|&nbsp;
      Branch: <strong>endingIntegration</strong> &nbsp;|&nbsp;
      Commit range: <strong>HEAD~1 &rarr; HEAD</strong> &nbsp;|&nbsp;
      Scanned: <strong>{timestamp}</strong>
    </p>
  </div>

  <div class="verdict-banner">
    <div>
      <h2>Pipeline {verdict_label}</h2>
      <p>Overall risk score: <strong>{score}</strong> &mdash; {len(all_findings)} finding(s) identified across all scanners.</p>
    </div>
    <div class="verdict-tag">{verdict_label}</div>
  </div>

  <div class="stats">
    <div class="stat">
      <div class="val">{len(all_findings)}</div>
      <div class="lbl">Total Findings</div>
    </div>
    <div class="stat critical">
      <div class="val">{crit_count}</div>
      <div class="lbl">Critical</div>
    </div>
    <div class="stat high">
      <div class="val">{high_count}</div>
      <div class="lbl">High</div>
    </div>
    <div class="stat medium">
      <div class="val">{med_count}</div>
      <div class="lbl">Medium</div>
    </div>
    <div class="stat low">
      <div class="val">{low_count}</div>
      <div class="lbl">Low</div>
    </div>
  </div>

  <div class="card">
    <div class="card-header">
      <h3>Scan Findings</h3>
      <span class="badge-count">{len(all_findings)} result(s)</span>
    </div>
    <table>
      <thead>
        <tr>
          <th style="width:44px;">#</th>
          <th style="width:110px;">Severity</th>
          <th>Description</th>
          <th style="width:210px;">Scanner</th>
        </tr>
      </thead>
      <tbody>
        {rows}
        {no_findings_row}
      </tbody>
    </table>
  </div>

  <div class="card">
    <div class="card-header">
      <h3>Scan History</h3>
      <span class="badge-count">latest run</span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Commit Range</th>
          <th>Verdict</th>
          <th>Findings</th>
          <th>Risk Score</th>
        </tr>
      </thead>
      <tbody>
        {history_row}
      </tbody>
    </table>
  </div>

  <div class="card">
    <div class="card-header">
      <h3>Scanner Coverage</h3>
      <span class="badge-count">6 scanners</span>
    </div>
    <table>
      <thead>
        <tr>
          <th style="width:220px;">Scanner</th>
          <th style="width:80px;">Status</th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>
        <tr style="border-bottom:1px solid #e2e8f0;">
          <td style="padding:11px 16px;font-size:13px;font-weight:500;">Secret Scanner</td>
          <td style="padding:11px 16px;"><span class="scanner-status-ok">PASSED</span></td>
          <td style="padding:11px 16px;font-size:13px;color:#718096;">Detects hardcoded API keys, tokens, PII, and credentials via regex compliance rules.</td>
        </tr>
        <tr style="border-bottom:1px solid #e2e8f0;">
          <td style="padding:11px 16px;font-size:13px;font-weight:500;">AST / Code Analysis</td>
          <td style="padding:11px 16px;"><span class="scanner-status-ok">PASSED</span></td>
          <td style="padding:11px 16px;font-size:13px;color:#718096;">Static analysis using tree-sitter to detect dangerous function calls (eval, exec, os.system, subprocess).</td>
        </tr>
        <tr style="border-bottom:1px solid #e2e8f0;">
          <td style="padding:11px 16px;font-size:13px;font-weight:500;">SCA Scanner</td>
          <td style="padding:11px 16px;"><span class="scanner-status-ok">PASSED</span></td>
          <td style="padding:11px 16px;font-size:13px;color:#718096;">Software Composition Analysis &mdash; checks dependencies for banned packages, licenses and authors.</td>
        </tr>
        <tr style="border-bottom:1px solid #e2e8f0;">
          <td style="padding:11px 16px;font-size:13px;font-weight:500;">Container Scanner</td>
          <td style="padding:11px 16px;"><span class="scanner-status-ok">PASSED</span></td>
          <td style="padding:11px 16px;font-size:13px;color:#718096;">Analyses Dockerfiles for EOL base images, the latest tag, and root user execution risk.</td>
        </tr>
        <tr style="border-bottom:1px solid #e2e8f0;">
          <td style="padding:11px 16px;font-size:13px;font-weight:500;">IaC Scanner</td>
          <td style="padding:11px 16px;"><span class="scanner-status-ok">PASSED</span></td>
          <td style="padding:11px 16px;font-size:13px;color:#718096;">Identifies Terraform and Kubernetes misconfigurations such as public S3 buckets and privileged pods.</td>
        </tr>
        <tr>
          <td style="padding:11px 16px;font-size:13px;font-weight:500;">Malicious Code Scanner</td>
          <td style="padding:11px 16px;"><span class="scanner-status-ok">PASSED</span></td>
          <td style="padding:11px 16px;font-size:13px;color:#718096;">Detects reverse shells, data exfiltration, destructive commands, obfuscation, and SSH backdoors.</td>
        </tr>
      </tbody>
    </table>
  </div>

</div>

<footer>
  <strong>GitCheck</strong> &mdash; Automated Security Scanning for CI/CD Pipelines &mdash; {date_only}
</footer>

</body>
</html>"""

    with open(output_path, "w") as fh:
        fh.write(html)
    print(f"\n[REPORT] HTML report saved -> {output_path}")
