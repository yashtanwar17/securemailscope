import json

class ThreatForensics:
    def __init__(self, report_data):
        self.report_data = report_data

    def export_json(self):
        return json.dumps(self.report_data, indent=4)

    def export_html(self):
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SecureMailScope Forensic Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }}
                h1, h2 {{ color: #38bdf8; }}
                .card {{ background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
                .badge {{ background: #ef4444; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }}
            </style>
        </head>
        <body>
            <h1>SecureMailScope: Cryptographic Security Assessment Report</h1>
            <div class="card">
                <h2>Executive Summary</h2>
                <p><strong>Overall Posture Score:</strong> {self.report_data['posture_score']} / 100</p>
                <p><strong>Risk Classification:</strong> <span class="badge">{self.report_data['classification']}</span></p>
                <p><strong>Anomaly Report:</strong> {self.report_data['ai_analysis'].get('anomaly_detection')}</p>
            </div>
            <div class="card">
                <h2>AI-Prioritized Recommendations</h2>
                <ul>
                    {"".join([f"<li>{rec}</li>" for rec in self.report_data['ai_analysis'].get('prioritized_recommendations', [])])}
                </ul>
            </div>
        </body>
        </html>
        """