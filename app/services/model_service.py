import hashlib
import joblib
import numpy as np
import pandas as pd
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


def _predict_probability(input_pca, model_name: str):
    if model_name == "ANN":
        legit_prob = float(ann_model.predict(input_pca, verbose=0)[0][0])
        return 1 - legit_prob

    elif model_name == "SVM":
        classes = list(svm_model.classes_)
        phishing_class = 0 if 0 in classes else -1
        phishing_index = classes.index(phishing_class)
        return float(svm_model.predict_proba(input_pca)[0][phishing_index])

    

    else:
        classes = list(rf_model.classes_)
        phishing_class = 0 if 0 in classes else -1
        phishing_index = classes.index(phishing_class)
        return float(rf_model.predict_proba(input_pca)[0][phishing_index])


def predict_phishing(url: str, model_name: str = "Random Forest"):
    cache_key = make_cache_key(url, model_name)

    # Redis cache is optional
    try:
        cached = get_cached_prediction(cache_key)
        if cached is not None:
            return cached
    except Exception as e:
        print(f"Redis cache read skipped: {e}")

    features_dict, feature_array = extract_all_features(url)

    input_array = np.array(feature_array).reshape(1, -1)
    input_scaled = scaler.transform(input_array)
    input_pca = pca.transform(input_scaled)

    phishing_prob = _predict_probability(input_pca, model_name)
    legitimate_prob = 1 - phishing_prob

    result = {
        "url": url,
        "model_used": model_name,
        "prediction": "Phishing"
        if phishing_prob >= settings.PHISHING_THRESHOLD
        else "Legitimate",
        "phishing_probability": round(phishing_prob * 100, 2),
        "legitimate_probability": round(legitimate_prob * 100, 2),
        "risk_level": get_risk_level(phishing_prob),
        "features": features_dict
    }

    # Redis cache is optional
    try:
        set_cached_prediction(cache_key, result)
    except Exception as e:
        print(f"Redis cache write skipped: {e}")

    return result


def predict_manual_features(features: list, model_name: str = "Random Forest"):
    input_array = np.array(features).reshape(1, -1)
    input_scaled = scaler.transform(input_array)
    input_pca = pca.transform(input_scaled)

    phishing_prob = _predict_probability(input_pca, model_name)
    legitimate_prob = 1 - phishing_prob

    return {
        "model_used": model_name,
        "prediction": "Phishing"
        if phishing_prob >= settings.PHISHING_THRESHOLD
        else "Legitimate",
        "phishing_probability": round(phishing_prob * 100, 2),
        "legitimate_probability": round(legitimate_prob * 100, 2),
        "risk_level": get_risk_level(phishing_prob)
    }


def predict_batch_csv(file, model_name: str = "Random Forest"):
    df = pd.read_csv(file.file)

    results = []

    if "url" in df.columns:
        for url in df["url"]:
            results.append(
                predict_phishing(str(url), model_name)
            )
    else:
        for _, row in df.iterrows():
            features = row.tolist()
            results.append(
                predict_manual_features(features, model_name)
            )

    return {
        "total_records": len(results),
        "results": results
    }


def evaluate_model(model_name: str = "Random Forest"):
    safe_model_name = model_name.lower().replace(" ", "_")

    return {
        "model_name": model_name,
        "message": "Model evaluation reports available.",
        "reports": {
            "model_summary": "/reports/model_summary.csv",
            "feature_summary": "/reports/feature_value_summary.csv",
            "roc_curve": "/reports/roc_curve_comparison.png",
            "model_comparison": "/reports/model_comparison_auc_accuracy.png",
            "class_distribution": "/reports/class_distribution.png",
            "correlation_heatmap": "/reports/correlation_heatmap.png",
            "confusion_matrix": f"/reports/{safe_model_name}_confusion_matrix.png"
        }
    }