"""
Static reference-layer enrichment: CWE (Common Weakness Enumeration) and
MITRE ATT&CK technique mapping.

This is intentionally NOT a live API integration — both CWE and ATT&CK are
large, slow-moving public knowledge bases (MITRE), and re-fetching them per
finding would add latency and a network dependency for no benefit. Instead
this module ships a small, hand-curated, keyword-based lookup table mapping
the finding categories this project's scanners actually produce to the
correct public identifiers, so every generated report can cite:

- A CWE ID + name + link (https://cwe.mitre.org/data/definitions/<id>.html)
  describing the *class* of weakness.
- One or more MITRE ATT&CK technique IDs + tactic + link
  (https://attack.mitre.org/techniques/<id>/) describing how that weakness
  class is used by real adversaries, per MITRE's public ATT&CK framework.

Coverage is deliberately conservative: several finding categories genuinely
have no well-established formal CWE/ATT&CK mapping (e.g. a purely
informational security.txt discovery, or an open port with no known risky
service). Those are left unenriched (``cwe=None``, ``mitre_attack=[]``)
rather than forcing a misleading label onto them — a missing mapping is more
honest than a wrong one.
"""
from __future__ import annotations

from typing import Any

CWE_BASE_URL = "https://cwe.mitre.org/data/definitions/{id}.html"
ATTACK_BASE_URL = "https://attack.mitre.org/techniques/{anchor}/"
OWASP_BASE_URL = "https://owasp.org/Top10/{anchor}/"


def _cwe(cwe_id: str, name: str) -> dict[str, str]:
    return {"id": f"CWE-{cwe_id}", "name": name, "url": CWE_BASE_URL.format(id=cwe_id)}


def _technique(tid: str, name: str, tactic: str) -> dict[str, str]:
    return {
        "id": tid,
        "name": name,
        "tactic": tactic,
        "url": ATTACK_BASE_URL.format(anchor=tid.replace(".", "/")),
    }


def _owasp(code: str, name: str, anchor: str) -> dict[str, str]:
    """OWASP Top 10 (2021) category — https://owasp.org/Top10/"""
    return {"id": code, "name": name, "url": OWASP_BASE_URL.format(anchor=anchor)}


A03 = _owasp("A03:2021", "Injection", "A03_2021-Injection")
A05 = _owasp("A05:2021", "Security Misconfiguration", "A05_2021-Security_Misconfiguration")
A01 = _owasp("A01:2021", "Broken Access Control", "A01_2021-Broken_Access_Control")
A02 = _owasp("A02:2021", "Cryptographic Failures", "A02_2021-Cryptographic_Failures")
A04 = _owasp("A04:2021", "Insecure Design", "A04_2021-Insecure_Design")
A06 = _owasp("A06:2021", "Vulnerable and Outdated Components", "A06_2021-Vulnerable_and_Outdated_Components")
A07 = _owasp("A07:2021", "Identification and Authentication Failures", "A07_2021-Identification_and_Authentication_Failures")


# Ordered rule list: the first rule whose keyword appears in the finding's
# combined title/evidence/source-module text wins. More specific keywords
# (e.g. "sql injection") are listed before generic ones (e.g. "open ")
# so specific findings never get demoted to a generic mapping.
_RULES: list[tuple[list[str], dict[str, str], list[dict[str, str]], dict[str, str]]] = [
    (["local_file_inclusion", "local file inclusion", "path traversal"],
     _cwe("22", "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"),
     [_technique("T1005", "Data from Local System", "Collection"),
      _technique("T1083", "File and Directory Discovery", "Discovery")],
     A03),

    (["default_credentials", "default credentials"],
     _cwe("798", "Use of Hard-coded Credentials"),
     [_technique("T1078.001", "Valid Accounts: Default Accounts", "Defense Evasion")],
     A07),

    (["open_redirect", "open redirect"],
     _cwe("601", "URL Redirection to Untrusted Site ('Open Redirect')"),
     [_technique("T1204", "User Execution", "Execution")],
     A01),

    (["tls-invalid-cert", "شهادة tls غير صالحة", "certificate has expired", "certificate_valid", "invalid or expired tls"],
     _cwe("295", "Improper Certificate Validation"),
     [_technique("T1557", "Adversary-in-the-Middle", "Collection")],
     A02),

    (["sql injection", "sqli"],
     _cwe("89", "Improper Neutralization of Special Elements used in an SQL Command"),
     [_technique("T1190", "Exploit Public-Facing Application", "Initial Access")],
     A03),

    (["reflected xss", "cross-site scripting", " xss", "xss "],
     _cwe("79", "Improper Neutralization of Input During Web Page Generation"),
     [_technique("T1190", "Exploit Public-Facing Application", "Initial Access"),
      _technique("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")],
     A03),

    (["x-frame-options"],
     _cwe("1021", "Improper Restriction of Rendered UI Layers or Frames"),
     [_technique("T1189", "Drive-by Compromise", "Initial Access")],
     A05),

    (["missing security header", "content-security-policy", "strict-transport-security",
      "x-content-type-options", "referrer-policy", "permissions-policy"],
     _cwe("693", "Protection Mechanism Failure"),
     [_technique("T1189", "Drive-by Compromise", "Initial Access")],
     A05),

    (["cors"],
     _cwe("346", "Origin Validation Error"),
     [_technique("T1190", "Exploit Public-Facing Application", "Initial Access")],
     A05),

    (["cookie"],
     _cwe("614", "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"),
     [_technique("T1539", "Steal Web Session Cookie", "Credential Access")],
     A05),

    (["exposed-env", ".env", "exposed environment"],
     _cwe("538", "Insertion of Sensitive Information into Externally-Accessible File"),
     [_technique("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access")],
     A05),

    (["git-head", ".git/head", "git repository exposed", "git-exposure"],
     _cwe("538", "Insertion of Sensitive Information into Externally-Accessible File"),
     [_technique("T1213", "Data from Information Repositories", "Collection")],
     A05),

    (["swagger", "openapi", "api documentation exposed"],
     _cwe("200", "Exposure of Sensitive Information to an Unauthorized Actor"),
     [_technique("T1595.002", "Active Scanning: Vulnerability Scanning", "Reconnaissance")],
     A05),

    (["schema mismatch", "schema validation"],
     _cwe("20", "Improper Input Validation"),
     [_technique("T1190", "Exploit Public-Facing Application", "Initial Access")],
     A04),

    (["api authentication", "missing authentication", "unauthenticated", "authentication missing", "authorization"],
     _cwe("306", "Missing Authentication for Critical Function"),
     [_technique("T1190", "Exploit Public-Facing Application", "Initial Access"),
      _technique("T1078", "Valid Accounts", "Defense Evasion")],
     A01),

    (["mfa", "multi-factor", "single-factor"],
     _cwe("308", "Use of Single-Factor Authentication"),
     [_technique("T1078", "Valid Accounts", "Defense Evasion"),
      _technique("T1621", "Multi-Factor Authentication Request Generation", "Credential Access")],
     A07),

    (["telnet"],
     _cwe("319", "Cleartext Transmission of Sensitive Information"),
     [_technique("T1040", "Network Sniffing", "Credential Access"),
      _technique("T1552", "Unsecured Credentials", "Credential Access")],
     A02),

    (["ftp"],
     _cwe("319", "Cleartext Transmission of Sensitive Information"),
     [_technique("T1040", "Network Sniffing", "Credential Access")],
     A02),

    (["rdp", "3389/tcp", "remote desktop"],
     _cwe("287", "Improper Authentication"),
     [_technique("T1133", "External Remote Services", "Initial Access"),
      _technique("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement")],
     A07),

    (["smb", "445/tcp", "netbios"],
     _cwe("287", "Improper Authentication"),
     [_technique("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement")],
     A07),

    (["vulnerable", "cve-", "nse security indicator", "nse finding"],
     _cwe("1104", "Use of Unmaintained Third Party Components"),
     [_technique("T1210", "Exploitation of Remote Services", "Lateral Movement")],
     A06),

    # Generic fallback for any other open network service — kept last and
    # deliberately broad, since raw port exposure alone is only ever a
    # reconnaissance-stage concern, not an exploit.
    (["open ", "/tcp", "/udp"],
     _cwe("200", "Exposure of Sensitive Information to an Unauthorized Actor"),
     [_technique("T1595", "Active Scanning", "Reconnaissance")],
     A05),
]


def match_cwe_attack(text: str) -> tuple[dict[str, str] | None, list[dict[str, str]], dict[str, str] | None]:
    """Return (cwe, mitre_attack, owasp) for a lowercase-insensitive haystack
    of title/evidence/source-module text, or (None, [], None) if nothing
    matches."""
    haystack = text.lower()
    for keywords, cwe, techniques, owasp in _RULES:
        if any(kw in haystack for kw in keywords):
            return cwe, techniques, owasp
    return None, [], None


def _haystack_for(title: str, evidence: str, source_module: str) -> str:
    return " ".join((title or "", evidence or "", source_module or ""))


def enrich_finding_dict(finding: dict[str, Any]) -> dict[str, Any]:
    """Mutate a finding dict in place (used by the dict-based
    ``finding_pipeline`` / single-module async scan path), attaching
    ``cwe``, ``mitre_attack``, and ``owasp``. Safe no-op if already present."""
    if finding.get("cwe") or finding.get("mitre_attack"):
        return finding
    haystack = _haystack_for(str(finding.get("title", "")), str(finding.get("evidence", "")), str(finding.get("source_module", "")))
    cwe, techniques, owasp = match_cwe_attack(haystack)
    finding["cwe"] = cwe
    finding["mitre_attack"] = techniques
    finding["owasp"] = owasp
    return finding


def enrich_normalized_finding(finding: Any) -> Any:
    """Mutate a ``NormalizedFinding`` pydantic object in place (used by the
    full-assessment ``normalizer.normalize_bundle`` path)."""
    evidence_text = " ".join(e.evidence for e in getattr(finding, "evidence", []) if getattr(e, "evidence", None))
    haystack = _haystack_for(finding.title, evidence_text, finding.source_module)
    cwe, techniques, owasp = match_cwe_attack(haystack)
    finding.cwe = cwe
    finding.mitre_attack = techniques
    finding.owasp = owasp
    return finding
