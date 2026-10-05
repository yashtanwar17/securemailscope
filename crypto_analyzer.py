class CryptoAnalyzer:
    def __init__(self, session_data):
        self.sessions = session_data.get("sessions", [])

    def analyze_cryptography(self):
        findings = []
        weak_cipher_count = 0
        deprecated_tls_count = 0

        for idx, session in enumerate(self.sessions):
            versions = session.get("tls_versions", [])
            ciphers = session.get("ciphers", [])
            
            # Check for deprecated TLS
            for ver in versions:
                if ver in ["TLS 1.0", "TLS 1.1"]:
                    deprecated_tls_count += 1
                    findings.append({
                        "severity": "HIGH",
                        "category": "Deprecated Protocol",
                        "description": f"Session {idx+1} ({session['protocol']}) negotiated {ver}, which is vulnerable to POODLE and BEAST attacks."
                    })
            
            # Check for weak ciphers or STARTTLS downgrade risks
            if session.get("protocol") == "SMTP (Plain/STARTTLS)" and not session.get("starttls_detected"):
                findings.append({
                    "severity": "CRITICAL",
                    "category": "STARTTLS Stripping Vulnerability",
                    "description": f"Session {idx+1}: SMTP session on port 25 failed to negotiate or enforce STARTTLS upgrade."
                })

            if not versions:
                findings.append({
                    "severity": "CRITICAL",
                    "category": "Cleartext Transmission",
                    "description": f"Session {idx+1} ({session['protocol']}) operated entirely in plain text without TLS encryption."
                })

        return {
            "weak_cipher_count": weak_cipher_count,
            "deprecated_tls_count": deprecated_tls_count,
            "crypto_findings": findings
        }