class PostureAI:
    def __init__(self, crypto_findings, cert_audit, ai_insights):
        self.crypto_findings = crypto_findings
        self.cert_audit = cert_audit
        self.ai_insights = ai_insights

    def generate_final_report(self):
        return {
            "posture_score": self.ai_insights.get("risk_score", 45),
            "classification": self.ai_insights.get("risk_classification", "CRITICAL"),
            "crypto_findings": self.crypto_findings,
            "certificate_audit": self.cert_audit,
            "ai_analysis": self.ai_insights
        }