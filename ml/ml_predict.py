import joblib

MODEL_PATH = "ml/models/cybersentry_url_model_v2.joblib"
FEATURES_PATH = "ml/models/cybersentry_url_features_v2.joblib"

model = joblib.load(MODEL_PATH)
feature_names = joblib.load(FEATURES_PATH)


def predict(features):
    values = [features[name] for name in feature_names]

    prediction = int(model.predict([values])[0])
    probabilities = model.predict_proba([values])[0]

    # Dataset mapping:
    # 0 = Phishing
    # 1 = Legitimate
    phishing_probability = float(probabilities[0])
    legitimate_probability = float(probabilities[1])

    return {
        "prediction": prediction,
        "label": "Phishing" if prediction == 0 else "Legitimate",
        "phishing_probability": round(phishing_probability, 4),
        "legitimate_probability": round(legitimate_probability, 4),
        "risk_score": round(phishing_probability * 100, 2),
    }