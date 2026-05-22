import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT_DIR))

import streamlit as st
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
import joblib
import warnings
warnings.filterwarnings('ignore')

from keras.models import load_model
from sklearn.metrics import (
    roc_curve, auc, classification_report,
    ConfusionMatrixDisplay,
    precision_score, recall_score,
    f1_score, accuracy_score,
    roc_auc_score
)

from app.services.feature_extraction import extract_all_features

# ============================================================
# Load Models & Preprocessing Objects
# ============================================================
ann_model = load_model("app/models/ann_model.h5")
rf_model  = joblib.load("app/models/rf_model.pkl")
svm_model = joblib.load("app/models/svm_model.pkl")
scaler    = joblib.load("app/models/scaler.pkl")
pca       = joblib.load("app/models/pca.pkl")

# ============================================================
# Page Config
# ============================================================

st.set_page_config(page_title="PhishNet – Phishing Detector", layout="centered")

# Dark Theme
st.markdown("""
<style>
.stApp {background-color:#0E1117; color:white;}
h1,h2,h3,h4,p,label,div {color:white;}
[data-testid="stSidebar"] {background-color:#161B22;}
.stButton>button {background:#262730;color:white;border-radius:8px;}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ PhishNet – Phishing Website Detector")
st.markdown("Detect if a website is **Legitimate ✅** or **Phishing 🚨** using ML & Deep Learning.")

# ============================================================
# Model Selector (shared across all tabs)
# ============================================================
model_choice = st.radio(
    "🔍 Choose a model to predict with:",
    ["ANN", "Random Forest", "SVM"]
)

# ============================================================
# Helper: run prediction given a feature array
# ============================================================
PHISHING_CLASS = 0   # model classes are [0, 1]

def run_prediction(feature_array):
    input_array  = np.array(feature_array).reshape(1, -1)
    input_scaled = scaler.transform(input_array)
    input_pca    = pca.transform(input_scaled)

    if model_choice == "ANN":
        legit_prob = float(ann_model.predict(input_pca, verbose=0)[0][0])
        phishing_prob = 1 - legit_prob

    elif model_choice == "Random Forest":
        classes = list(rf_model.classes_)
        phishing_index = classes.index(PHISHING_CLASS)
        phishing_prob = rf_model.predict_proba(input_pca)[0][phishing_index]

    elif model_choice == "SVM":
        classes = list(svm_model.classes_)
        phishing_index = classes.index(PHISHING_CLASS)
        phishing_prob = svm_model.predict_proba(input_pca)[0][phishing_index]

   

    return float(phishing_prob)


def explain_prediction(features_dict):
    explanation_rows = []

    for feature, value in features_dict.items():
        if value == -1:
            impact = "Increases phishing risk 🚨"
            reason = "This feature shows suspicious/phishing behavior."
        elif value == 0:
            impact = "Moderate risk ⚠️"
            reason = "This feature is doubtful or suspicious."
        else:
            impact = "Supports legitimate ✅"
            reason = "This feature looks safe/normal."

        explanation_rows.append({
            "Feature": feature,
            "Value": value,
            "Impact": impact,
            "Explanation": reason
        })

    return pd.DataFrame(explanation_rows)

# ============================================================
# TABS
# ============================================================
tab1, tab2, tab3, tab4 = st.tabs([
    "🔗 URL Auto-Scan",
    "✍️ Manual Feature Input",
    "📤 Batch CSV Prediction",
    "📊 Model Evaluation"
])

# ----------------------------------------------------------
# TAB 1 — URL Auto-Scan
# ----------------------------------------------------------
with tab1:
    st.subheader("🔗 Automatic URL Analysis")
    st.markdown(
        "Enter any URL and all **30 phishing-detection features** will be extracted "
        "automatically, then fed into the selected ML model."
    )

    url_input = st.text_input(
        "Enter URL to scan:",
        placeholder="https://www.example.com"
    )

    if st.button("🔍 Analyze URL", key="analyze_url"):
        if not url_input.strip():
            st.warning("⚠️ Please enter a URL first.")
        else:
            with st.spinner("Extracting 30 features from URL… this may take ~15 seconds."):
                try:
                    features_dict, feature_array = extract_all_features(url_input.strip())

                    # Show extracted features in a table
                    st.subheader("📋 Extracted Features")
                    feat_df = pd.DataFrame(
                        list(features_dict.items()),
                        columns=["Feature", "Value"]
                    )
                    feat_df["Meaning"] = feat_df["Value"].map(
                        {1: "✅ Legitimate", 0: "⚠️ Suspicious", -1: "🚨 Phishing"}
                    )
                    st.dataframe(feat_df, use_container_width=True)

                    # Predict
                    prob  = run_prediction(feature_array)
                    label = "Phishing 🚨" if prob > 0.5 else "Legitimate ✅"

                    st.divider()
                    if prob > 0.5:
                        st.error(f"🚨 **Result: {label}**")
                    else:
                        st.success(f"✅ **Result: {label}**")

                    col1, col2 = st.columns(2)
                    col1.metric("Phishing Probability", f"{prob * 100:.2f} %")
                    col2.metric("Legitimate Probability", f"{(1 - prob) * 100:.2f} %")

                    st.subheader("🧠 Explainable AI Report")

                    xai_df = explain_prediction(features_dict)

                    st.dataframe(xai_df, use_container_width=True)

                    dangerous_count = (xai_df["Value"] == -1).sum()
                    safe_count = (xai_df["Value"] == 1).sum()
                    suspicious_count = (xai_df["Value"] == 0).sum()

                    st.markdown("### 🔎 Explanation Summary")
                    st.write(f"🚨 Dangerous features: {dangerous_count}")
                    st.write(f"⚠️ Suspicious features: {suspicious_count}")
                    st.write(f"✅ Safe features: {safe_count}")

                    top_risky = xai_df[xai_df["Value"] == -1]["Feature"].head(5).tolist()

                    if len(top_risky) > 0:
                        st.warning("Top risky features: " + ", ".join(top_risky))
                    else:
                        st.success("No highly dangerous feature detected.")

                    # Risk badge
                    if prob > 0.8:
                        st.error("🔴 Risk Level: CRITICAL")
                    elif prob > 0.6:
                        st.warning("🟠 Risk Level: HIGH")
                    elif prob > 0.4:
                        st.warning("🟡 Risk Level: MEDIUM")
                    else:
                        st.success("🟢 Risk Level: LOW")

                except Exception as e:
                    st.error(f"⚠️ Feature extraction failed: {e}")


# ----------------------------------------------------------
# TAB 2 — Manual Feature Input
# ----------------------------------------------------------
with tab2:
    st.subheader("✍️ Enter Feature Values Manually")

    st.markdown(
        """
        Enter all 30 phishing-detection feature values manually.

        ### Feature Value Meaning
        - ✅ `1`  → Legitimate / Safe
        - ⚠️ `0`  → Suspicious
        - 🚨 `-1` → Phishing / Dangerous
        """
    )

    FEATURE_NAMES = [
        "UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//",
        "PrefixSuffix-", "SubDomains", "HTTPS", "DomainRegLen", "Favicon",
        "NonStdPort", "HTTPSDomainURL", "RequestURL", "AnchorURL",
        "LinksInScriptTags", "ServerFormHandler", "InfoEmail", "AbnormalURL",
        "WebsiteForwarding", "StatusBarCust", "DisableRightClick",
        "UsingPopupWindow", "IframeRedirection", "AgeofDomain", "DNSRecording",
        "WebsiteTraffic", "PageRank", "GoogleIndex", "LinksPointingToPage",
        "StatsReport"
    ]

    cols = st.columns(3)
    user_input = []

    for i, name in enumerate(FEATURE_NAMES):
        with cols[i % 3]:
            val = st.number_input(
                label=name,
                min_value=-1,
                max_value=1,
                value=0,
                step=1,
                key=f"feat_{i}"
            )
            user_input.append(int(val))

    if st.button("🔎 Predict", key="predict_manual"):
        try:
            prob = run_prediction(user_input)

            label = "Phishing 🚨" if prob > 0.5 else "Legitimate ✅"

            st.divider()

            if prob > 0.5:
                st.error(f"🚨 Prediction: **{label}**")
            else:
                st.success(f"✅ Prediction: **{label}**")

            col1, col2 = st.columns(2)

            col1.metric(
                "🚨 Phishing Probability",
                f"{prob * 100:.2f}%"
            )

            col2.metric(
                "🛡️ Legitimate Probability",
                f"{(1 - prob) * 100:.2f}%"
            )

            # Risk Level
            if prob > 0.8:
                st.error("🔴 Risk Level: CRITICAL")
            elif prob > 0.6:
                st.warning("🟠 Risk Level: HIGH")
            elif prob > 0.4:
                st.warning("🟡 Risk Level: MEDIUM")
            else:
                st.success("🟢 Risk Level: LOW")

        except Exception as e:
            st.error(f"⚠️ Error during prediction: {e}")

# ----------------------------------------------------------
# TAB 3 — Batch CSV Prediction
# ----------------------------------------------------------
with tab3:
    st.subheader("📤 Batch Prediction")

    batch_mode = st.radio(
        "CSV format:",
        ["30 pre-extracted features", "URLs only (auto-extract features)"]
    )

    uploaded_file = st.file_uploader("Upload CSV", type=["csv"])

    if uploaded_file is not None:
        try:
            df_uploaded = pd.read_csv(uploaded_file)

            if batch_mode == "30 pre-extracted features":
                if df_uploaded.shape[1] != 30:
                    st.error("❌ CSV must contain exactly 30 feature columns.")
                else:
                    X_scaled = scaler.transform(df_uploaded)
                    X_pca    = pca.transform(X_scaled)

                    if model_choice == "ANN":
                        probs = ann_model.predict(X_pca).flatten()
                    elif model_choice == "Random Forest":
                        probs = rf_model.predict_proba(X_pca)[:, 1]
                    elif model_choice == "SVM":
                        probs = svm_model.predict_proba(X_pca)[:, 1]
                   

                    labels = ["Phishing 🚨" if p > 0.5 else "Legitimate ✅" for p in probs]
                    result_df = df_uploaded.copy()
                    result_df["Probability"] = probs
                    result_df["Prediction"]  = labels

                    st.success(f"✅ Predictions completed for {len(result_df)} rows.")
                    st.dataframe(result_df)
                    csv = result_df.to_csv(index=False).encode("utf-8")
                    st.download_button("📥 Download Results", csv, "phishing_predictions.csv", "text/csv")

            else:
                # URL-only CSV; column must be named 'url'
                if "url" not in df_uploaded.columns:
                    st.error("❌ CSV must have a column named 'url'.")
                else:
                    results = []
                    progress = st.progress(0)
                    total = len(df_uploaded)

                    for idx, row in df_uploaded.iterrows():
                        url = row["url"]
                        try:
                            features_dict, feature_array = extract_all_features(url)
                            prob  = run_prediction(feature_array)
                            label = "Phishing 🚨" if prob > 0.5 else "Legitimate ✅"
                            risk  = ("CRITICAL 🔴" if prob > 0.8 else
                                     "HIGH 🟠"     if prob > 0.6 else
                                     "MEDIUM 🟡"   if prob > 0.4 else "LOW 🟢")
                            results.append({"URL": url, "Prediction": label,
                                            "Phishing_Prob_%": f"{prob*100:.2f}",
                                            "Risk": risk, **features_dict})
                        except Exception as e:
                            results.append({"URL": url, "Prediction": "Error",
                                            "Phishing_Prob_%": "N/A",
                                            "Risk": "UNKNOWN", "Error": str(e)})
                        progress.progress((idx + 1) / total)

                    result_df = pd.DataFrame(results)
                    st.success(f"✅ Processed {total} URLs.")
                    st.dataframe(result_df)
                    csv = result_df.to_csv(index=False).encode("utf-8")
                    st.download_button("📥 Download Results", csv, "phishing_url_results.csv", "text/csv")

        except Exception as e:
            st.error(f"⚠️ File processing error: {e}")


# ----------------------------------------------------------
# TAB 4 — Model Evaluation
# ----------------------------------------------------------
with tab4:
    @st.cache_data
    def load_data():
        df=pd.read_csv("data/phishing.csv")
        X  = df.drop(["Index", "class"], axis=1)
        y  = df["class"]
        X_scaled = scaler.transform(X)
        X_pca    = pca.transform(X_scaled)
        return train_test_split(X_pca, y, test_size=0.2, random_state=42)

    X_train, X_test, y_train, y_test = load_data()

    def get_probs(model_name, X):
        if model_name == "ANN":
            return ann_model.predict(X).flatten()
        elif model_name == "Random Forest":
            return rf_model.predict_proba(X)[:, 1]
        elif model_name == "SVM":
            return svm_model.predict_proba(X)[:, 1]
        

    # ROC Curve
    st.subheader("📊 ROC Curve")
    if st.checkbox("Show ROC Curve for Test Set"):
        try:
            probs = get_probs(model_choice, X_test)
            fpr, tpr, _ = roc_curve(y_test, probs)
            roc_auc_val = auc(fpr, tpr)

            fig, ax = plt.subplots()
            ax.plot(fpr, tpr, color="darkorange", lw=2,
                    label=f"ROC curve (AUC = {roc_auc_val:.2f})")
            ax.plot([0, 1], [0, 1], color="navy", lw=2, linestyle="--")
            ax.set_xlim([0.0, 1.0]); ax.set_ylim([0.0, 1.05])
            ax.set_xlabel("False Positive Rate")
            ax.set_ylabel("True Positive Rate")
            ax.set_title(f"ROC Curve – {model_choice}")
            ax.legend(loc="lower right")
            st.pyplot(fig)
        except Exception as e:
            st.error(f"⚠️ Could not generate ROC: {e}")

    # Confusion Matrix
    st.subheader("📈 Confusion Matrix & Classification Report")
    if st.checkbox("Show Confusion Matrix and Classification Report"):
        try:
            probs = get_probs(model_choice, X_test)
            preds = probs > 0.5
            report    = classification_report(y_test, preds, output_dict=True)
            report_df = pd.DataFrame(report).transpose()
            st.write("### Classification Report")
            st.dataframe(report_df)

            fig, ax = plt.subplots()
            ConfusionMatrixDisplay.from_predictions(
                y_test, preds, ax=ax, cmap="Blues", normalize="true"
            )
            ax.set_title(f"{model_choice} Confusion Matrix (Normalized)")
            st.pyplot(fig)
        except Exception as e:
            st.error(f"⚠️ Error displaying metrics: {e}")

    # All-Model Summary
    st.subheader("📊 Final Model Performance Summary")
    if st.checkbox("Show Summary Comparison for All Models"):
        try:
            ann_probs  = get_probs("ANN", X_test);          ann_pred  = ann_probs  > 0.5
            rf_probs   = get_probs("Random Forest", X_test); rf_pred   = rf_probs   > 0.5
            svm_probs  = get_probs("SVM", X_test);           svm_pred  = svm_probs  > 0.5
            models_list = ["ANN", "Random Forest", "SVM"]
            all_probs = [ann_probs, rf_probs, svm_probs]
            all_preds = [ann_pred, rf_pred, svm_pred]

            summary_df = pd.DataFrame({
                "Model":        models_list,
                "AUC Score":    [roc_auc_score(y_test, p) for p in all_probs],
                "Accuracy (%)": [accuracy_score(y_test, p) * 100 for p in all_preds],
                "Precision":    [precision_score(y_test, p) for p in all_preds],
                "Recall":       [recall_score(y_test, p)    for p in all_preds],
                "F1-Score":     [f1_score(y_test, p)        for p in all_preds],
            })

            st.dataframe(summary_df.style.format({
                "AUC Score": "{:.3f}", "Accuracy (%)": "{:.2f}",
                "Precision": "{:.3f}", "Recall": "{:.3f}", "F1-Score": "{:.3f}"
            }))

            x     = np.arange(len(models_list))
            width = 0.13
            fig, ax = plt.subplots(figsize=(12, 6))
            metrics = [
                (summary_df["AUC Score"] * 100, "AUC Score (%)",  "mediumslateblue", -2*width),
                (summary_df["Accuracy (%)"],     "Accuracy (%)",   "mediumseagreen",  -width),
                (summary_df["Precision"] * 100,  "Precision (%)",  "coral",            0),
                (summary_df["Recall"] * 100,     "Recall (%)",     "gold",             width),
                (summary_df["F1-Score"] * 100,   "F1-Score (%)",   "orchid",           2*width),
            ]
            for vals, label, color, offset in metrics:
                bars = ax.bar(x + offset, vals, width, label=label, color=color)
                for bar in bars:
                    h = bar.get_height()
                    ax.annotate(f"{h:.1f}",
                                xy=(bar.get_x() + bar.get_width() / 2, h),
                                xytext=(0, 3), textcoords="offset points",
                                ha="center", va="bottom", fontsize=7)

            ax.set_xlabel("Model"); ax.set_ylabel("Score (%)")
            ax.set_title("Model Comparison: Metrics Overview")
            ax.set_xticks(x); ax.set_xticklabels(models_list)
            ax.legend(); ax.grid(axis="y", linestyle="--", alpha=0.7)
            plt.tight_layout()
            st.pyplot(fig)

        except Exception as e:
            st.error(f"⚠️ Error generating summary comparison: {e}")
