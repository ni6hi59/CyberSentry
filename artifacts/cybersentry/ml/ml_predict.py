"""CyberSentry Random Forest prediction layer."""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd


# -------------------------------------------------------------------
# Model paths
# -------------------------------------------------------------------

ML_DIR = Path(__file__).resolve().parent

PROJECT_DIR = ML_DIR.parent

MODEL_PATH = (
    PROJECT_DIR
    / "models"
    / "cybersentry_random_forest.joblib"
)

FEATURE_ORDER_PATH = (
    PROJECT_DIR
    / "models"
    / "cybersentry_feature_order.json"
)


# -------------------------------------------------------------------
# Model loading
# -------------------------------------------------------------------

MODEL = None
FEATURE_ORDER = None
LOAD_ERROR = None


def _load_model() -> None:
    """Load the verified CyberSentry model and feature order."""

    global MODEL
    global FEATURE_ORDER
    global LOAD_ERROR

    try:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"ML model not found: {MODEL_PATH}"
            )

        if not FEATURE_ORDER_PATH.exists():
            raise FileNotFoundError(
                f"Feature-order file not found: "
                f"{FEATURE_ORDER_PATH}"
            )

        MODEL = joblib.load(
            MODEL_PATH
        )

        with open(
            FEATURE_ORDER_PATH,
            "r",
            encoding="utf-8",
        ) as file:
            FEATURE_ORDER = json.load(
                file
            )

        if not isinstance(
            FEATURE_ORDER,
            list,
        ):
            raise ValueError(
                "Feature-order file must contain a list."
            )

        if len(FEATURE_ORDER) != 23:
            raise ValueError(
                "CyberSentry expects exactly "
                f"23 features, found "
                f"{len(FEATURE_ORDER)}."
            )

        # Verify that the model exposes the expected API.
        if not hasattr(
            MODEL,
            "predict",
        ):
            raise ValueError(
                "Loaded object does not provide predict()."
            )

        if not hasattr(
            MODEL,
            "predict_proba",
        ):
            raise ValueError(
                "Loaded model does not provide predict_proba()."
            )

        LOAD_ERROR = None

    except Exception as error:
        MODEL = None
        FEATURE_ORDER = None
        LOAD_ERROR = str(error)


_load_model()


# -------------------------------------------------------------------
# Public prediction function
# -------------------------------------------------------------------

def predict(
    features: dict,
) -> dict:
    """
    Predict whether a URL is phishing or legitimate.

    Dataset mapping:
        0 = Phishing
        1 = Legitimate
    """

    if MODEL is None or FEATURE_ORDER is None:
        return {
            "available": False,
            "prediction": None,
            "prediction_label": "Unavailable",
            "phishing_probability": None,
            "legitimate_probability": None,
            "status": "ML model unavailable",
            "error": LOAD_ERROR,
        }

    try:
        # Make sure every required feature exists.
        missing_features = [
            name
            for name in FEATURE_ORDER
            if name not in features
        ]

        if missing_features:
            raise ValueError(
                "Missing ML features: "
                + ", ".join(
                    missing_features
                )
            )

        # Build the input in EXACT training order.
        values = {
            name: [
                features[name]
            ]
            for name in FEATURE_ORDER
        }

        input_frame = pd.DataFrame(
            values,
            columns=FEATURE_ORDER,
        )

        # Prediction
        prediction = int(
            MODEL.predict(
                input_frame
            )[0]
        )

        # Probabilities
        probabilities = MODEL.predict_proba(
            input_frame
        )[0]

        classes = list(
            MODEL.classes_
        )

        probability_map = {
            int(class_value): float(probability)
            for class_value, probability
            in zip(
                classes,
                probabilities,
            )
        }

        phishing_probability = (
            probability_map.get(
                0,
                0.0,
            )
        )

        legitimate_probability = (
            probability_map.get(
                1,
                0.0,
            )
        )

        prediction_label = (
            "Phishing"
            if prediction == 0
            else "Legitimate"
        )

        return {
            "available": True,

            "prediction": prediction,

            "prediction_label":
                prediction_label,

            "phishing_probability":
                round(
                    phishing_probability
                    * 100,
                    2,
                ),

            "legitimate_probability":
                round(
                    legitimate_probability
                    * 100,
                    2,
                ),

            "status":
                "Random Forest model connected",

            "error": None,
        }

    except Exception as error:
        return {
            "available": False,
            "prediction": None,
            "prediction_label": "Unavailable",
            "phishing_probability": None,
            "legitimate_probability": None,
            "status": "ML prediction failed",
            "error": str(error),
      }
