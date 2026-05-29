from __future__ import annotations

from app.schemas.scan import MITREResult, MITRETactic, RiskLevel, ScanResponse, ScanType

# MITRE ATT&CK technique registry: id → (id, name, tactic)
_TECHNIQUES: dict[str, tuple[str, str, str]] = {
    "T1566":     ("T1566",     "Phishing",                   "Initial Access"),
    "T1566.001": ("T1566.001", "Spearphishing Attachment",   "Initial Access"),
    "T1566.002": ("T1566.002", "Spearphishing Link",         "Initial Access"),
    "T1036":     ("T1036",     "Masquerading",               "Defense Evasion"),
    "T1204.001": ("T1204.001", "Malicious Link",             "Execution"),
    "T1598":     ("T1598",     "Phishing for Information",   "Reconnaissance"),
    "T1539":     ("T1539",     "Steal Web Session Cookie",   "Credential Access"),
    "T1078":     ("T1078",     "Valid Accounts",             "Defense Evasion"),
    "T1589.002": ("T1589.002", "Email Addresses",            "Reconnaissance"),
}


def _tactic(key: str, reason: str) -> MITRETactic:
    tid, name, tactic = _TECHNIQUES[key]
    return MITRETactic(technique_id=tid, technique_name=name, tactic=tactic, reason=reason)


class MITREMapperService:
    """
    Maps scan findings to MITRE ATT&CK techniques.

    Uses a rule-based approach: each detection signal from threat intel,
    typosquatting, URL analysis, and email auth maps to one or more
    ATT&CK techniques. Results are deduplicated by technique ID.
    """

    def map(self, result: ScanResponse) -> MITREResult:
        tactics: list[MITRETactic] = []
        added: set[str] = set()

        def add(key: str, reason: str) -> None:
            if key not in added:
                tactics.append(_tactic(key, reason))
                added.add(key)

        risk = result.risk_score

        # Any suspicious or malicious scan → base phishing tactic
        if risk and risk.level in (RiskLevel.SUSPICIOUS, RiskLevel.MALICIOUS):
            add("T1566", "Overall risk level indicates phishing activity")

        # High-risk URLs with credential harvesting patterns
        if result.url_analysis and result.url_analysis.high_risk_urls:
            add("T1566.002", "High-risk URLs with credential keywords or redirect chains detected")
            add("T1204.001", "Malicious links crafted to trick users into clicking")

        # URL credential keywords → information phishing
        if result.url_analysis:
            for feat in result.url_analysis.analyzed_urls:
                if feat.has_credential_keywords:
                    add("T1598", "Credential-harvesting keywords found in URL path")
                    break

        # Typosquatting → masquerading as known brand
        if result.typosquatting and result.typosquatting.is_typosquatting:
            best = result.typosquatting.matches[0] if result.typosquatting.matches else None
            brand = best.brand if best else "known brand"
            add("T1036", f"Domain impersonates '{brand}' — typosquatting with edit distance {best.distance if best else '?'}")

        # Phishing keyword density → information gathering
        if result.keywords and result.keywords.total_weight >= 5:
            cats = ", ".join(result.keywords.categories)
            add("T1598", f"High phishing keyword density ({result.keywords.total_weight} weight) across categories: {cats}")

        # Domain mismatch (From ≠ Reply-To) → session cookie / credential theft
        if result.email_auth and result.email_auth.domain_mismatch:
            add("T1539", (
                f"From/Reply-To domain mismatch may redirect victims to attacker-controlled "
                f"domain ({result.email_auth.reply_to_domain})"
            ))

        # Email scan → sender address reconnaissance
        if result.scan_type == ScanType.EMAIL:
            add("T1589.002", "Email header analysis reveals sender spoofing and routing anomalies")

        # High VirusTotal detection count → compromised infrastructure
        for ti in result.threat_intel:
            if ti.raw_data and ti.raw_data.get("malicious", 0) >= 3:
                add("T1078", "High malicious engine count suggests compromised or attacker-controlled infrastructure")
                break

        return MITREResult(techniques=tactics)
