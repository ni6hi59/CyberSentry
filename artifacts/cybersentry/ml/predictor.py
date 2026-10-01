"""Fail-closed interface for a verified CyberSentry phishing URL model."""

from __future__ import annotations

from pathlib import Path
from threading import RLock
from typing import Any

from .feature_extractor import FEATURE_NAMES

# Google Colab exports must be placed at:
# artifacts/cybersentry/ml/model/phishing_url_model.joblib
# Only trusted joblib artifacts trained on FEATURE_NAMES, in this exact order,
# with class labels "legitimate" and "phishing" are eligible for prediction.
MODEL_PATH = Path(__file__).resolve().parent / "model" / "phishing_url_model.joblib"

_MODEL_LOCK = RLock()
_LOADED_MODEL: Any = None
_LOADED_SIGNATURE: tuple[int, int] | None = None


def _empty_result(status: str) -> dict[str, Any]:
    return {
        "prediction": None,
        "phishing_probability": None,
        "legitimate_probability": None,
        "model_status": status,
    }


def _load_model() -> tuple[Any | None, str]:
    global _LOADED_MODEL, _LOADED_SIGNATURE

    if not MODEL_PATH.is_file():
        return None, "ML model not connected yet"

    try:
        stat = MODEL_PATH.stat()
        signature = (stat.st_mtime_ns, stat.st_size)
    except OSError:
        return None, "ML model file is unavailable"

    with _MODEL_LOCK:
        if _LOADED_MODEL is not None and _LOADED_SIGNATURE == signature:
            return _LOADED_MODEL, "Connected"

        try:
            # joblib uses Python pickle internally. Load only the artifact explicitly
            # placed at MODEL_PATH by a trusted project owner.
            import joblib

            model = joblib.load(MODEL_PATH)
        except Exception:
            _LOADED_MODEL = None
            _LOADED_SIGNATURE = None
            return None, "ML model file could not be loaded"

        _LOADED_MODEL = model
        _LOADED_SIGNATURE = signature
        return model, "Connected"


def predict_url(features: dict[str, int | float]) -> dict[str, Any]:
    """Predict from the 23-feature vector, or return an explicit unavailable state.

    No heuristic or placeholder prediction is used when no compatible model is
    present. A model is considered connected only after its feature schema,
    probability interface, and class labels have all been validated.
    """
    model, status = _load_model()
    if model is None:
        return _empty_result(status)

    if not isinstance(features, dict) or any(name not in features for name in FEATURE_NAMES):
        return _empty_result("ML feature vector is incomplete")

    model_feature_names = getattr(model, "feature_names_in_", None)
    if model_feature_names is not None and tuple(str(name) for name in model_feature_names) != FEATURE_NAMES:
        return _empty_result("ML model feature order does not match CyberSentry")

    model_feature_count = getattr(model, "n_features_in_", None)
    if model_feature_count is not None and int(model_feature_count) != len(FEATURE_NAMES):
        return _empty_result("ML model must accept exactly 23 URL features")

    try:
        row = [[float(features[name]) for name in FEATURE_NAMES]]
        classes = list(model.classes_)
        class_names = [str(label).strip().casefold() for label in classes]
        phishing_index = class_names.index("phishing")
        legitimate_index = class_names.index("legitimate")
        probabilities = list(model.predict_proba(row)[0])
        prediction = str(model.predict(row)[0]).strip().casefold()
        if len(probabilities) != len(class_names) or prediction not in {"phishing", "legitimate"}:
            return _empty_result("ML model output is incompatible")
        phishing_probability = float(probabilities[phishing_index])
        legitimate_probability = float(probabilities[legitimate_index])
    except (AttributeError, IndexError, TypeError, ValueError, RuntimeError):
        return _empty_result("ML model is incompatible with the 23-feature contract")
    except Exception:
        return _empty_result("ML model prediction failed")

    return {
        "prediction": prediction,
        "phishing_probability": phishing_probability,
        "legitimate_probability": legitimate_probability,
        "model_status": "Connected",
    }