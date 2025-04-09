from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
import time

# === Severity Color Mapping ===
severity_colors = {
    "Low": colors.blue,
    "Medium": colors.orange,
    "High": colors.red
}

# === Vulnerability Mitigations Dictionary ===
mitigations = {
    # Existing
    "CSP: Failure to Define Directive with No Fallback": {
        "Low": "Add default-src fallback in your CSP header.",
        "Medium": "Define fallback directives and test with CSP evaluators.",
        "High": "Apply strict CSP policy including fallback for all directives."
    },
    "Content Security Policy (CSP) Header Not Set": {
        "Low": "Add basic CSP header to limit script sources.",
        "Medium": "Define CSP with self and trusted sources only.",
        "High": "Enforce CSP with nonce-based or hash-based values."
    },
    "Cross-Domain Misconfiguration": {
        "Low": "Restrict cross-origin resource sharing to known domains.",
        "Medium": "Use strict Access-Control-Allow-Origin headers.",
        "High": "Deny cross-origin access unless explicitly required and validated."
    },
    "Hidden File Found": {
        "Low": "Remove unnecessary files from the server.",
        "Medium": "Block access to hidden/system files.",
        "High": "Scan deployment pipeline to exclude hidden/test files."
    },
    "Cross-Domain JavaScript Source File Inclusion": {
        "Low": "Avoid including scripts from external sources unnecessarily.",
        "Medium": "Verify all third-party scripts and use integrity attributes.",
        "High": "Self-host all scripts, review code, and restrict dynamic inclusion."
    },
    "Timestamp Disclosure - Unix": {
        "Low": "Avoid exposing file modification timestamps.",
        "Medium": "Configure server to hide detailed headers.",
        "High": "Audit exposed metadata and sanitize all server responses."
    },
    "Information Disclosure - Suspicious Comments": {
        "Low": "Remove developer comments before deployment.",
        "Medium": "Audit source for hardcoded secrets or debug info.",
        "High": "Use automated scanning tools to catch sensitive info leaks."
    },
    "Modern Web Application": {
        "Low": "Monitor new technologies used and review security.",
        "Medium": "Perform security reviews for modern frameworks.",
        "High": "Implement security policies for modern stacks, frameworks, and APIs."
    },
    "User Agent Fuzzer": {
        "Low": "Filter and validate User-Agent headers.",
        "Medium": "Rate-limit suspicious User-Agent patterns.",
        "High": "Detect and block abnormal requests, apply WAF rules."
    },

    # OWASP Top 10 (2021)
    "Broken Access Control": {
        "Low": "Review access permissions and enforce least privilege.",
        "Medium": "Use secure frameworks and centralize access control.",
        "High": "Implement access control checks on server-side for every request."
    },
    "Cryptographic Failures": {
        "Low": "Use HTTPS and secure headers.",
        "Medium": "Use proven libraries and avoid deprecated algorithms.",
        "High": "Encrypt all sensitive data at rest and in transit."
    },
    "Injection": {
        "Low": "Escape input properly.",
        "Medium": "Use parameterized queries and ORM.",
        "High": "Sanitize all user inputs and validate on both client and server side."
    },
    "Insecure Design": {
        "Low": "Review system designs for potential risks.",
        "Medium": "Apply threat modeling and design validation.",
        "High": "Redesign critical systems using secure architecture principles."
    },
    "Security Misconfiguration": {
        "Low": "Disable unnecessary features and services.",
        "Medium": "Implement security headers and update dependencies.",
        "High": "Automate configuration and perform regular audits."
    },
    "Vulnerable and Outdated Components": {
        "Low": "Update packages regularly.",
        "Medium": "Use dependency scanners and alerts.",
        "High": "Remove unsupported components and apply patches quickly."
    },
    "Identification and Authentication Failures": {
        "Low": "Avoid weak passwords and use session timeouts.",
        "Medium": "Implement MFA and lockout policies.",
        "High": "Enforce strong authentication and monitor for brute force attempts."
    },
    "Software and Data Integrity Failures": {
        "Low": "Verify dependencies.",
        "Medium": "Use signed packages and secure deployment.",
        "High": "Implement CI/CD pipeline integrity checks."
    },
    "Security Logging and Monitoring Failures": {
        "Low": "Log important actions.",
        "Medium": "Monitor logs and use alerting.",
        "High": "Integrate SIEM tools and ensure alert responses."
    },
    "Server-Side Request Forgery (SSRF)": {
        "Low": "Validate and sanitize URLs.",
        "Medium": "Block internal IP address access.",
        "High": "Use allowlist for URLs and deny local network access."
    }
}

# === Mitigation Fetcher ===
def get_mitigation(vuln_name, severity):
    return mitigations.get(vuln_name, {}).get(severity, "No specific mitigation found. Follow OWASP guidelines.")

# === PDF Report Generator ===
def save_to_pdf(alerts, filename="final_vuln_report.pdf"):
    c = canvas.Canvas(filename, pagesize=letter)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, 770, "🔍 ZAP Vulnerability Scan Report")
    c.setFont("Helvetica", 12)
    c.drawString(50, 755, f"Target: {alerts[0]['url'] if alerts else 'Unknown'}")  # Adjusted to use alert URL
    c.drawString(50, 740, f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    y = 710
    for alert in alerts:
        name = alert['alert']
        severity = alert['risk']
        desc = alert['description'][:500] + "..." if len(alert['description']) > 500 else alert['description']
        mitigation = get_mitigation(name, severity)
        color = severity_colors.get(severity, colors.black)

        c.setFillColor(color)
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, f"Vulnerability: {name} ({severity})")
        c.setFillColor(colors.black)
        c.setFont("Helvetica", 11)
        c.drawString(50, y - 15, f"Description: {desc}")
        c.drawString(50, y - 30, f"Mitigation: {mitigation}")

        y -= 80
        if y < 100:
            c.showPage()
            y = 750

    c.save()
    print(f"\n✅ PDF report saved as '{filename}'")