from flask import Flask, request, render_template
import numpy as np
import pickle
import warnings
import socket
from feature import FeatureExtraction

warnings.filterwarnings('ignore')

app = Flask(__name__)
gbc = None

# Global list to store scan history
history_log = []

# Load Model
try:
    with open("pickle/model.pkl", "rb") as file:
        gbc = pickle.load(file)
except:
    print("Error: Model not found. Please run train_model.py first.")

@app.route("/", methods=["GET", "POST"])
def index():
    global history_log
    
    if request.method == "POST":
        url = request.form["url"]
        
        try:
            # 1. Feature Extraction
            obj = FeatureExtraction(url)
            x = np.array(obj.getFeaturesList()).reshape(1, 30) 
            details = obj.get_url_details()

            # 2. Hard Rule: Raw IP Address Detection
            is_ip = False
            try:
                ip_part = details['domain'].split(':')[0]
                socket.inet_aton(ip_part)
                is_ip = True
            except:
                is_ip = False

            # 3. Prediction Logic
            if is_ip:
                y_pro_non_phishing = 0.01 # Force Unsafe
                details['registrar'] = "Raw IP Detected"
                details['risk_flags'].append("Direct IP Access")
            else:
                y_pro_non_phishing = gbc.predict_proba(x)[0, 1]

            # 4. Prepare Result Data
            result_status = "Safe" if y_pro_non_phishing >= 0.5 else "Unsafe"
            
            # Calculate Display Confidence (e.g. 98.5)
            if result_status == "Safe":
                conf_percent = round(y_pro_non_phishing * 100, 1)
            else:
                conf_percent = round((1 - y_pro_non_phishing) * 100, 1)
            
            # 5. Save Record for History
            new_record = {
                "url": url,
                "status": result_status,
                "confidence": conf_percent,
                "original_score": round(y_pro_non_phishing, 2),
                "domain": details['domain'],
                "ip_address": details.get('ip_address', 'Hidden'),
                "age_years": details.get('age_years', 0),
                "location": details.get('server_location', 'Unknown'),
                "registrar": details.get('registrar', 'Unknown'),
                "risk_flags": details.get('risk_flags', [])
            }
            
            # Add to top of list and limit to 5 items
            history_log.insert(0, new_record)
            history_log = history_log[:5] 

            return render_template('index.html', xx=round(y_pro_non_phishing, 2), url=url, details=details, history=history_log)
        
        except Exception as e:
            return render_template('index.html', xx=-1, error=str(e), history=history_log)
    
    return render_template("index.html", xx=-1, history=history_log)

if __name__ == "__main__":
    app.run(debug=True)