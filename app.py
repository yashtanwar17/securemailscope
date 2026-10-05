import os
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
from pcap_engine import PCAPEngine
from crypto_analyzer import CryptoAnalyzer
from crypto_auditor import CryptoAuditor
from gemini_ai import GeminiAIEngine
from posture_ai import PostureAI
from threat_forensics import ThreatForensics
import io

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_pcap():
    if 'pcap_file' not in request.files:
        return jsonify({"error": "No PCAP file uploaded"}), 400
    
    file = request.files['pcap_file']
    if file.filename == '':
        return jsonify({"error": "Selected file is invalid"}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    try:
        # Run Pipeline
        engine = PCAPEngine(filepath)
        traffic_data = engine.parse_traffic()

        analyzer = CryptoAnalyzer(traffic_data)
        crypto_res = analyzer.analyze_cryptography()

        auditor = CryptoAuditor(traffic_data.get("sessions", []))
        audit_res = auditor.audit_posture()

        ai_engine = GeminiAIEngine()
        ai_insights = ai_engine.assess_risk_and_recommend({
            "traffic": traffic_data,
            "crypto_findings": crypto_res,
            "certificates": audit_res
        })

        posture = PostureAI(crypto_res, audit_res, ai_insights)
        final_report = posture.generate_final_report()

        # Store in session or temporary cache for export
        app.config['LAST_REPORT'] = final_report

        return jsonify(final_report)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/export/<file_format>')
def export_report(file_format):
    report = app.config.get('LAST_REPORT')
    if not report:
        return "No analysis report available.", 404

    forensics = ThreatForensics(report)
    if file_format == 'json':
        output = forensics.export_json()
        return send_file(io.BytesIO(output.encode()), mimetype='application/json', as_attachment=True, download_name='securemailscope_report.json')
    elif file_format == 'html':
        output = forensics.export_html()
        return send_file(io.BytesIO(output.encode()), mimetype='text/html', as_attachment=True, download_name='securemailscope_report.html')
    else:
        return "Invalid format", 400

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)