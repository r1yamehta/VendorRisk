from flask import Flask, request, jsonify # type: ignore
from flask_cors import CORS # type: ignore
import requests

app = Flask(__name__)
CORS(app)  # allows frontend to connect

# Home route (just to avoid 404)
@app.route('/')
def home():
    return "VendorRisk AI Backend Running 🚀"

# Main API
@app.route('/analyze', methods=['GET'])
def analyze():
    vendor = request.args.get('vendor')

    if not vendor:
        return jsonify({"error": "Vendor name required"}), 400

    try:
        # NVD API call
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={vendor}"
        res = requests.get(url)
        data = res.json()

        total = data.get("totalResults", 0)

        # Risk Logic
        if total > 50:
            score = 84
            level = "High"
        elif total > 10:
            score = 51
            level = "Medium"
        else:
            score = 16
            level = "Low"

        return jsonify({
            "vendor": vendor,
            "vulnerabilities": total,
            "risk_score": score,
            "risk_level": level,
            "source": "NVD (Real-time)"
        })

    except Exception as e:
        return jsonify({
            "error": "Failed to fetch data",
            "details": str(e)
        }), 500


if __name__ == '__main__':
    app.run(debug=True)