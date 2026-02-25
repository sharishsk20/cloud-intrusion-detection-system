from flask import Flask, request, jsonify, render_template_string
import joblib
import pandas as pd
import warnings
import os

# Suppress warnings for a cleaner cloud log
warnings.filterwarnings("ignore")

app = Flask(__name__)

# 1. LOAD THE TRAINED ASSETS
print("🛰️  Loading C-IDS Engine from .joblib files...")
model = joblib.load('cids_rf_model.joblib')
le = joblib.load('cids_label_encoder.joblib')

# Global variable to store the latest result for the UI
last_audit = {
    "status": "Waiting",
    "action": "SYSTEM IDLE",
    "class": "No Active Traffic",
    "confidence": "0%"
}

# 2. THE DASHBOARD UI (HOMEPAGE)
@app.route('/')
def home():
    # Dynamic color switching based on the last action
    status_color = "#5cb85c" if last_audit['action'] == "ALLOW" else "#d9534f"
    if last_audit['action'] == "SYSTEM IDLE": status_color = "#5bc0de"

    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>C-IDS Cloud Dashboard</title>
        <meta http-equiv="refresh" content="3"> <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; text-align: center; padding: 50px; background: #1a1a2e; color: white; }}
            .card {{ background: #16213e; padding: 40px; border-radius: 20px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); display: inline-block; border: 2px solid {status_color}; }}
            h1 {{ margin-bottom: 10px; color: #e94560; }}
            .status-box {{ font-size: 32px; font-weight: bold; margin: 20px 0; padding: 10px; border-radius: 10px; background: {status_color}; color: white; }}
            .details {{ text-align: left; margin-top: 20px; font-size: 18px; }}
            .footer {{ margin-top: 30px; font-size: 12px; color: #888; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>🛰️ C-IDS Live Auditor</h1>
            <p>Cloud-Native Intrusion Detection Engine</p>
            <div class="status-box">{last_audit['action']}</div>
            <div class="details">
                <p><b>🛡️ Profile:</b> {last_audit['class']}</p>
                <p><b>📈 Confidence:</b> {last_audit['confidence']}</p>
                <p><b>📡 Status:</b> Operational</p>
            </div>
            <p class="footer">Real-time inference active via Render Cloud</p>
        </div>
    </body>
    </html>
    """
    return render_template_string(html_template)

# 3. THE SCAN ENDPOINT
@app.route('/scan', methods=['POST'])
def scan_packet():
    global last_audit
    try:
        data = request.get_json()
        features = data['features']
        
        feature_cols = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 
                        'dst_bytes', 'count', 'srv_count', 'same_srv_rate', 'diff_srv_rate']
        input_df = pd.DataFrame([features], columns=feature_cols)

        # Run Inference
        prediction = model.predict(input_df)[0]
        prob = model.predict_proba(input_df).max()
        
        attack_type = le.inverse_transform([prediction])[0]
        final_action = 'ALLOW' if attack_type == 'normal' else 'BLOCK'

        # Update the Global variable so the UI sees it
        last_audit = {
            "status": "Active",
            "action": final_action,
            "class": attack_type.upper(),
            "confidence": f"{prob*100:.2f}%"
        }

        print(f"📊 Audit Result: {attack_type.upper()} -> {final_action}")

        return jsonify({
            'status': 'success',
            'classification': attack_type.upper(),
            'confidence': last_audit['confidence'],
            'action': final_action
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

if __name__ == '__main__':
    # Bind to PORT provided by Render
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
