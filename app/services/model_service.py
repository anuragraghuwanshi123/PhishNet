import hashlib
import joblib
import numpy as np
from tensorflow.keras.models import load_model

from app.core.config import settings
from app.cache.redis_cache import set_cached_prediction, get_cached_prediction
from app.services.feature_extraction import extract_all_features


rf_model = joblib.load(settings.RF_MODEL_PATH)
svm_model = joblib.load(settings.SVM_MODEL_PATH)
scaler = joblib.load(settings.SCALER_PATH)
pca = joblib.load(settings.PCA_PATH)
ann_model = load_model(settings.ANN_MODEL_PATH)


def make_cache_key(url: str, model_name: str):
    raw_key = f"{url}_{model_name}"
    return hashlib.md5(raw_key.encode()).hexdigest()


def get_risk_level(phishing_prob: float):
    if phishing_prob >= 0.8:
        return "CRITICAL"
    elif phishing_prob >= 0.6:
        return "HIGH"
    elif phishing_prob >= 0.4:
        return "MEDIUM"
    return "LOW"


def predict_phishing(url: str, model_name: str = "Random Forest"):
    cache_key = make_cache_key(url, model_name)

    cached = get_cached_prediction(cache_key)
    if cached:
        return cached

    features_dict, feature_array = extract_all_features(url)

    input_array = np.array(feature_array).reshape(1, -1)
    input_scaled = scaler.transform(input_array)
    input_pca = pca.transform(input_scaled)

    if model_name == "ANN":
        legit_prob = float(ann_model.predict(input_pca, verbose=0)[0][0])
        phishing_prob = 1 - legit_prob

    elif model_name == "SVM":
        classes = list(svm_model.classes_)
        phishing_class = 0 if 0 in classes else -1
        phishing_index = classes.index(phishing_class)
        phishing_prob = float(svm_model.predict_proba(input_pca)[0][phishing_index])

    else:
        classes = list(rf_model.classes_)
        phishing_class = 0 if 0 in classes else -1
        phishing_index = classes.index(phishing_class)
        phishing_prob = float(rf_model.predict_proba(input_pca)[0][phishing_index])

    legitimate_prob = 1 - phishing_prob
    prediction = "Phishing" if phishing_prob >= settings.PHISHING_THRESHOLD else "Legitimate"

    result = {
        "url": url,
        "model_used": model_name,
        "prediction": prediction,
        "phishing_probability": round(phishing_prob * 100, 2),
        "legitimate_probability": round(legitimate_prob * 100, 2),
        "risk_level": get_risk_level(phishing_prob),
        "features": features_dict
    }

    set_cached_prediction(cache_key, result)

    return result