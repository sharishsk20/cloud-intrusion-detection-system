from flask import Flask, request, jsonify
import joblib
import pandas as pd
import warnings

# Suppress warnings for a cleaner cloud log
warnings.filterwarnings("ignore")

app = Flask(__name__)

# 1. LOAD THE TRAINED ASSETS
print("🛰️  Loading C-IDS Engine from .joblib files...")
model = joblib.load('cids_rf_model.joblib')
le = joblib.load('cids_label_encoder.joblib')

# 2. DEFINE THE CLOUD ENDPOINT
@app.route('/scan', methods=['POST'])
def scan_packet():
    try:
        # Get JSON data from the request
        data = request.get_json()
        features = data['features'] # Expecting a list of 10 feature values
        
        # Convert to DataFrame to match the training feature names
        feature_cols = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 
                        'dst_bytes', 'count', 'srv_count', 'same_srv_rate', 'diff_srv_rate']
        input_df = pd.DataFrame([features], columns=feature_cols)

        # Run Inference
        prediction = model.predict(input_df)[0]
        confidence = model.predict_proba(input_df).max()
        
        # Translate the numerical result back to the attack category
        attack_type = le.inverse_transform([prediction])[0]

        return jsonify({
            'status': 'success',
            'classification': attack_type.upper(),
            'confidence': f"{confidence*100:.2f}%",
            'action': 'BLOCK' if attack_type != 'normal' else 'ALLOW'
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000)) 
    
    # Set debug=False for deployment to prevent security leaks
    # Use 0.0.0.0 to make the server accessible externally
    app.run(host='0.0.0.0', port=port, debug=False)