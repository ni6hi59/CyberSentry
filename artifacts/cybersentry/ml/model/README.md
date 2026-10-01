# Google Colab model placement

Export the trained model from Google Colab as a trusted `joblib` artifact and
place it at:

`artifacts/cybersentry/ml/model/phishing_url_model.joblib`

The model must accept the 23 numeric values in the exact order defined by
`ml/feature_extractor.py`'s `FEATURE_NAMES`, expose `predict_proba`, and use the
class labels `legitimate` and `phishing`. `predictor.py` checks this contract
before it reports a prediction as connected. Until that file is present and
compatible, predictions and probabilities remain unavailable.

The tracked legacy file `artifacts/cybersentry/cybersentry_url_model.joblib` is
not loaded automatically. Its input schema is undocumented in this application,
so it must not be treated as the 23-feature model without verification.

Joblib files use Python pickle serialization. Only place model artifacts from a
trusted source in this directory.