
import os
import re
import ssl
import socket
import requests
import whois
import dns.resolver
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime
import pandas as pd


# helper functions
def get_domain(url):
    """Extract domain from URL"""
    parsed = urlparse(url)
    return parsed.netloc or parsed.path.split('/')[0]


def get_soup(url):
    """Get page HTML content"""
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        return BeautifulSoup(response.text, 'html.parser'), response
    except:
        return None, None



# FEATURE 1: UsingIP

def using_ip(url):
    ip_pattern = re.compile(
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])'
    )
    match = re.search(ip_pattern, url)
    if match:
        return -1
    return 1


# FEATURE 2: LongURL

def long_url(url):
    length = len(url)
    if length < 54:
        return 1
    elif 54 <= length <= 75:
        return 0
    return -1


# FEATURE 3: ShortURL

def short_url(url):
    shortening_services = [
        'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly',
        'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee'
    ]
    domain = get_domain(url).lower()
    for service in shortening_services:
        if service in domain:
            return -1
    return 1


# FEATURE 4: Symbol@

def symbol_at(url):
    if '@' in url:
        return -1
    return 1


# FEATURE 5: Redirecting//

def redirecting_double_slash(url):
    url_without_protocol = url.split('://')[1] if '://' in url else url
    if '//' in url_without_protocol:
        return -1
    return 1


# FEATURE 6: PrefixSuffix-

def prefix_suffix(url):
    domain = get_domain(url)
    if '-' in domain:
        return -1
    return 1


# FEATURE 7: SubDomains

def sub_domains(url):
    domain = get_domain(url)
    domain = domain.replace('www.', '')
    dot_count = domain.count('.')
    if dot_count == 1:
        return 1
    elif dot_count == 2:
        return 0
    return -1

# FEATURE 8: HTTPS

def https_check(url):
    domain = get_domain(url)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expire_date = datetime.strptime(
                    cert['notAfter'], '%b %d %H:%M:%S %Y %Z'
                )
                if expire_date > datetime.now():
                    return 1
    except:
        pass
    return -1


# FEATURE 9: DomainRegLen

def domain_reg_len(url):
    domain = get_domain(url)
    try:
        w = whois.whois(domain)
        exp_date = w.expiration_date
        if isinstance(exp_date, list):
            exp_date = exp_date[0]
        if exp_date:
            remaining = (exp_date - datetime.now()).days
            if remaining > 365:
                return 1
    except:
        pass
    return -1


# FEATURE 10: Favicon

def favicon(url):
    domain = get_domain(url)
    soup, _ = get_soup(url)
    if soup:
        for link in soup.find_all('link', rel='icon'):
            href = link.get('href', '')
            if href and domain not in href and href.startswith('http'):
                return -1
    return 1


# FEATURE 11: NonStdPort

def non_std_port(url):
    parsed = urlparse(url)
    port = parsed.port
    standard_ports = [80, 443, None]
    if port not in standard_ports:
        return -1
    return 1


# FEATURE 12: HTTPSDomainURL

def https_domain_url(url):
    domain = get_domain(url)
    if 'https' in domain.lower():
        return -1
    return 1


# FEATURE 13: RequestURL

def request_url(url):
    domain = get_domain(url)
    soup, _ = get_soup(url)
    if not soup:
        return -1

    total = 0
    external = 0

    tags = soup.find_all(['img', 'script', 'link'])
    for tag in tags:
        src = tag.get('src') or tag.get('href') or ''
        if src.startswith('http'):
            total += 1
            if domain not in src:
                external += 1

    if total == 0:
        return 1

    percentage = (external / total) * 100
    if percentage < 22:
        return 1
    elif 22 <= percentage <= 61:
        return 0
    return -1


# FEATURE 14: AnchorURL

def anchor_url(url):
    domain = get_domain(url)
    soup, _ = get_soup(url)
    if not soup:
        return -1

    total = 0
    unsafe = 0

    for a in soup.find_all('a', href=True):
        href = a['href']
        total += 1
        if href.startswith('http') and domain not in href:
            unsafe += 1
        elif href in ['#', '#content', '#skip', 'javascript::void(0)']:
            unsafe += 1

    if total == 0:
        return 1

    percentage = (unsafe / total) * 100
    if percentage < 31:
        return 1
    elif 31 <= percentage <= 67:
        return 0
    return -1


# FEATURE 15: LinksInScriptTags

def links_in_script_tags(url):
    domain = get_domain(url)
    soup, _ = get_soup(url)
    if not soup:
        return -1

    total = 0
    external = 0

    for tag in soup.find_all(['script', 'meta', 'link']):
        src = tag.get('src') or tag.get('href') or tag.get('content') or ''
        if 'http' in src:
            total += 1
            if domain not in src:
                external += 1

    if total == 0:
        return 1

    percentage = (external / total) * 100
    if percentage < 17:
        return 1
    elif 17 <= percentage <= 81:
        return 0
    return -1


# FEATURE 16: ServerFormHandler

def server_form_handler(url):
    domain = get_domain(url)
    soup, _ = get_soup(url)
    if not soup:
        return -1

    for form in soup.find_all('form', action=True):
        action = form['action']
        if not action or action == '#':
            return -1
        if 'about:blank' in action:
            return 0
        if action.startswith('http') and domain not in action:
            return -1

    return 1


# FEATURE 17: InfoEmail

def info_email(url):
    soup, response = get_soup(url)
    if not soup:
        return -1

    page_text = str(soup)
    if 'mailto:' in page_text:
        return -1
    return 1


# FEATURE 18: AbnormalURL

def abnormal_url(url):
    domain = get_domain(url)
    try:
        w = whois.whois(domain)
        if w.domain_name:
            whois_domain = w.domain_name
            if isinstance(whois_domain, list):
                whois_domain = whois_domain[0]
            if whois_domain.lower() in domain.lower():
                return 1
    except:
        pass
    return -1


# FEATURE 19: WebsiteForwarding

def website_forwarding(url):
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        redirect_count = len(response.history)
        if redirect_count <= 1:
            return 1
        elif 2 <= redirect_count <= 4:
            return 0
        return -1
    except:
        return -1


# FEATURE 20: StatusBarCust

def status_bar_cust(url):
    soup, _ = get_soup(url)
    if not soup:
        return -1

    page_text = str(soup)
    if 'onmouseover' in page_text.lower():
        return -1
    return 1


# FEATURE 21: DisableRightClick

def disable_right_click(url):
    soup, _ = get_soup(url)
    if not soup:
        return -1

    page_text = str(soup)
    if 'event.button==2' in page_text or 'contextmenu' in page_text:
        return -1
    return 1


# FEATURE 22: UsingPopupWindow

def using_popup_window(url):
    soup, _ = get_soup(url)
    if not soup:
        return -1

    page_text = str(soup)
    if 'window.open' in page_text and 'prompt(' in page_text:
        return -1
    return 1


# FEATURE 23: IframeRedirection

def iframe_redirection(url):
    soup, _ = get_soup(url)
    if not soup:
        return -1

    iframes = soup.find_all('iframe')
    for iframe in iframes:
        style = iframe.get('style', '')
        width = iframe.get('width', '100')
        height = iframe.get('height', '100')

        if ('display:none' in style or
            'visibility:hidden' in style or
            width == '0' or height == '0'):
            return -1

    if iframes:
        return 0
    return 1


# FEATURE 24: AgeofDomain

def age_of_domain(url):
    domain = get_domain(url)
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            if age_days > 180:
                return 1
    except:
        pass
    return -1


# FEATURE 25: DNSRecording

def dns_recording(url):
    domain = get_domain(url)
    try:
        dns.resolver.resolve(domain, 'A')
        return 1
    except:
        return -1


# FEATURE 26: WebsiteTraffic

def website_traffic(url):
    domain = get_domain(url)
    try:
        response = requests.get(
            f'https://api.similarweb.com/v1/website/{domain}/total-traffic-and-engagement/visits',
            timeout=5
        )
        if response.status_code == 200:
            return 1
    except:
        pass

    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200 and len(response.text) > 1000:
            return 0
    except:
        pass
    return -1



# FEATURE 27: PageRank

def page_rank(url):
    domain = get_domain(url)
    try:
        response = requests.get(
            f'https://openpagerank.com/api/v1.0/getPageRank?domains[]={domain}',
            headers={'API-OPR': 'YOUR_API_KEY'},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            rank = data['response'][0]['page_rank_integer']
            if rank >= 2:
                return 1
            return 0
    except:
        pass
    return -1


# FEATURE 28: GoogleIndex

def google_index(url):
    try:
        search_url = f'https://www.google.com/search?q=site:{url}'
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(search_url, headers=headers, timeout=10)

        if 'did not match any documents' not in response.text:
            return 1
        return -1
    except:
        return -1


# FEATURE 29: LinksPointingToPage

def links_pointing_to_page(url):
    try:
        domain = get_domain(url)
        response = requests.get(
            f'https://api.moz.com/links/v2/url_metrics',
            params={'target': domain},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            links = data.get('external_links', 0)
            if links > 2:
                return 1
            elif links >= 1:
                return 0
    except:
        pass
    return -1


# FEATURE 30: StatsReport

def stats_report(url):
    domain = get_domain(url)
    try:
        response = requests.post(
            'https://checkurl.phishtank.com/checkurl/',
            data={'url': url, 'format': 'json'},
            headers={'User-Agent': 'phishtank/check'},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            if data.get('results', {}).get('in_database'):
                return -1
    except:
        pass
    return 1



# MAIN FUNCTION: Extract ALL 30 Features from URL

def extract_all_features(url):
    print(f"\n Analyzing URL: {url}")
    print("=" * 60)

    features = {}

    print("Extracting features...")

    features['UsingIP']             = using_ip(url)
    print(f" Feature 1  - UsingIP: {features['UsingIP']}")

    features['LongURL']             = long_url(url)
    print(f" Feature 2  - LongURL: {features['LongURL']}")

    features['ShortURL']            = short_url(url)
    print(f" Feature 3  - ShortURL: {features['ShortURL']}")

    features['Symbol@']             = symbol_at(url)
    print(f" Feature 4  - Symbol@: {features['Symbol@']}")

    features['Redirecting//']       = redirecting_double_slash(url)
    print(f" Feature 5  - Redirecting//: {features['Redirecting//']}")

    features['PrefixSuffix-']       = prefix_suffix(url)
    print(f" Feature 6  - PrefixSuffix-: {features['PrefixSuffix-']}")

    features['SubDomains']          = sub_domains(url)
    print(f" Feature 7  - SubDomains: {features['SubDomains']}")

    features['HTTPS']               = https_check(url)
    print(f" Feature 8  - HTTPS: {features['HTTPS']}")

    features['DomainRegLen']        = domain_reg_len(url)
    print(f" Feature 9  - DomainRegLen: {features['DomainRegLen']}")

    features['Favicon']             = favicon(url)
    print(f" Feature 10 - Favicon: {features['Favicon']}")

    features['NonStdPort']          = non_std_port(url)
    print(f" Feature 11 - NonStdPort: {features['NonStdPort']}")

    features['HTTPSDomainURL']      = https_domain_url(url)
    print(f" Feature 12 - HTTPSDomainURL: {features['HTTPSDomainURL']}")

    features['RequestURL']          = request_url(url)
    print(f" Feature 13 - RequestURL: {features['RequestURL']}")

    features['AnchorURL']           = anchor_url(url)
    print(f" Feature 14 - AnchorURL: {features['AnchorURL']}")

    features['LinksInScriptTags']   = links_in_script_tags(url)
    print(f" Feature 15 - LinksInScriptTags: {features['LinksInScriptTags']}")

    features['ServerFormHandler']   = server_form_handler(url)
    print(f" Feature 16 - ServerFormHandler: {features['ServerFormHandler']}")

    features['InfoEmail']           = info_email(url)
    print(f" Feature 17 - InfoEmail: {features['InfoEmail']}")

    features['AbnormalURL']         = abnormal_url(url)
    print(f" Feature 18 - AbnormalURL: {features['AbnormalURL']}")

    features['WebsiteForwarding']   = website_forwarding(url)
    print(f" Feature 19 - WebsiteForwarding: {features['WebsiteForwarding']}")

    features['StatusBarCust']       = status_bar_cust(url)
    print(f" Feature 20 - StatusBarCust: {features['StatusBarCust']}")

    features['DisableRightClick']   = disable_right_click(url)
    print(f" Feature 21 - DisableRightClick: {features['DisableRightClick']}")

    features['UsingPopupWindow']    = using_popup_window(url)
    print(f" Feature 22 - UsingPopupWindow: {features['UsingPopupWindow']}")

    features['IframeRedirection']   = iframe_redirection(url)
    print(f" Feature 23 - IframeRedirection: {features['IframeRedirection']}")

    features['AgeofDomain']         = age_of_domain(url)
    print(f" Feature 24 - AgeofDomain: {features['AgeofDomain']}")

    features['DNSRecording']        = dns_recording(url)
    print(f" Feature 25 - DNSRecording: {features['DNSRecording']}")

    features['WebsiteTraffic']      = website_traffic(url)
    print(f" Feature 26 - WebsiteTraffic: {features['WebsiteTraffic']}")

    features['PageRank']            = page_rank(url)
    print(f" Feature 27 - PageRank: {features['PageRank']}")

    features['GoogleIndex']         = google_index(url)
    print(f" Feature 28 - GoogleIndex: {features['GoogleIndex']}")

    features['LinksPointingToPage'] = links_pointing_to_page(url)
    print(f" Feature 29 - LinksPointingToPage: {features['LinksPointingToPage']}")

    features['StatsReport']         = stats_report(url)
    print(f" Feature 30 - StatsReport: {features['StatsReport']}")

    feature_array = [
        features['UsingIP'],
        features['LongURL'],
        features['ShortURL'],
        features['Symbol@'],
        features['Redirecting//'],
        features['PrefixSuffix-'],
        features['SubDomains'],
        features['HTTPS'],
        features['DomainRegLen'],
        features['Favicon'],
        features['NonStdPort'],
        features['HTTPSDomainURL'],
        features['RequestURL'],
        features['AnchorURL'],
        features['LinksInScriptTags'],
        features['ServerFormHandler'],
        features['InfoEmail'],
        features['AbnormalURL'],
        features['WebsiteForwarding'],
        features['StatusBarCust'],
        features['DisableRightClick'],
        features['UsingPopupWindow'],
        features['IframeRedirection'],
        features['AgeofDomain'],
        features['DNSRecording'],
        features['WebsiteTraffic'],
        features['PageRank'],
        features['GoogleIndex'],
        features['LinksPointingToPage'],
        features['StatsReport']
    ]

    return features, feature_array


# EDA + Training + Evaluation Pipeline


import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import numpy as np
import matplotlib.pyplot as plt
import joblib

from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
    roc_auc_score,
    roc_curve,
    auc,
    precision_score,
    recall_score,
    f1_score,
)

try:
    from tensorflow.keras.models import Sequential, load_model
    from tensorflow.keras.layers import Dense
    from tensorflow.keras.callbacks import EarlyStopping
    TENSORFLOW_AVAILABLE = True
except Exception:
    TENSORFLOW_AVAILABLE = False


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


def run_eda(df, output_dir="reports"):
    os.makedirs(output_dir, exist_ok=True)

    print("\n" + "=" * 70)
    print("EDA REPORT")
    print("=" * 70)

    print("\nDataset Shape:", df.shape)
    print("\nFirst 5 rows:")
    print(df.head())

    print("\nDataset Info:")
    print(df.info())

    print("\nMissing Values:")
    print(df.isnull().sum())

    print("\nDuplicate Rows:", df.duplicated().sum())

    print("\nClass Distribution (raw):")
    print(df["class"].value_counts())
    print("\nClass Distribution (%):")
    print(df["class"].value_counts(normalize=True) * 100)

    plt.figure(figsize=(6, 4))
    df["class"].value_counts().sort_index().plot(kind="bar")
    plt.title("Class Distribution")
    plt.xlabel("Class")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "class_distribution.png"))
    plt.close()

    feature_df = df.drop(columns=["Index"], errors="ignore")
    corr = feature_df.corr(numeric_only=True)

    plt.figure(figsize=(14, 10))
    plt.imshow(corr, aspect="auto")
    plt.colorbar()
    plt.xticks(range(len(corr.columns)), corr.columns, rotation=90, fontsize=7)
    plt.yticks(range(len(corr.columns)), corr.columns, fontsize=7)
    plt.title("Feature Correlation Heatmap")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "correlation_heatmap.png"))
    plt.close()

    feature_cols = [col for col in FEATURE_NAMES if col in df.columns]
    feature_summary = df[feature_cols].apply(pd.Series.value_counts).fillna(0).astype(int)
    feature_summary.to_csv(os.path.join(output_dir, "feature_value_summary.csv"))

    print(f"\nEDA files saved inside: {output_dir}/")


def prepare_data(df, pca_components=16, model_dir="models"):
    X = df.drop(["Index", "class"], axis=1, errors="ignore")
    y = df["class"].copy()

    
    y = y.map({-1: 0, 0: 0, 1: 1})

    print("\nRemapped class distribution (0=Phishing, 1=Legitimate):")
    print(y.value_counts())

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    pca = PCA(n_components=pca_components)
    X_pca = pca.fit_transform(X_scaled)

    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(scaler, os.path.join(model_dir, "scaler.pkl"))
    joblib.dump(pca, os.path.join(model_dir, "pca.pkl"))

    print("\nScaler and PCA saved successfully.")
    print("Explained variance by PCA:", round(float(pca.explained_variance_ratio_.sum()), 4))

    return X_pca, y, scaler, pca


def train_ann(X_train, y_train, model_dir="models"):
    if not TENSORFLOW_AVAILABLE:
        print("\nTensorFlow/Keras not available. Skipping ANN training.")
        return None

    ann_model = Sequential()
    ann_model.add(Dense(6, activation="relu", input_dim=X_train.shape[1]))
    ann_model.add(Dense(6, activation="relu"))
    # sigmoid output → P(class=1) = P(Legitimate)
    ann_model.add(Dense(1, activation="sigmoid"))

    ann_model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])

    early_stop = EarlyStopping(
        monitor="val_loss",
        patience=3,
        restore_best_weights=True
    )

    ann_model.fit(
        X_train,
        y_train,
        epochs=50,
        batch_size=32,
        validation_split=0.1,
        callbacks=[early_stop],
        verbose=1
    )

    ann_path = os.path.join(model_dir, "ann_model.h5")
    ann_model.save(ann_path)
    print(f"ANN model saved at {ann_path}")
    return ann_model


def train_random_forest(X_train, y_train, model_dir="models"):
    rf_model = RandomForestClassifier(
        n_estimators=50,
        n_jobs=-1,
        random_state=42
    )
    rf_model.fit(X_train, y_train)

    rf_path = os.path.join(model_dir, "rf_model.pkl")
    joblib.dump(rf_model, rf_path)
    print(f"Random Forest model saved at {rf_path}")
    return rf_model


def train_svm(X_train, y_train, model_dir="models"):
    svm_model = SVC(probability=True, random_state=42)
    svm_model.fit(X_train, y_train)

    svm_path = os.path.join(model_dir, "svm_model.pkl")
    joblib.dump(svm_model, svm_path)
    print(f"SVM model saved at {svm_path}")
    return svm_model


def positive_class_probability(model, X):
    """Return P(legitimate) for sklearn models — class label 1."""
    classes = list(model.classes_)
    # After remapping, classes are always [0, 1]
    # class 1 = Legitimate
    positive_index = classes.index(1)
    return model.predict_proba(X)[:, positive_index]


def evaluate_models(models, X_test, y_test, output_dir="reports"):
    os.makedirs(output_dir, exist_ok=True)

    summary_rows = []
    probs_dict = {}
    preds_dict = {}

    for name, model in models.items():
        if model is None:
            continue

        if name == "ANN":
        
            legit_probs   = model.predict(X_test, verbose=0).flatten()
            phishing_probs = 1.0 - legit_probs          # P(phishing)
            probs = phishing_probs
        else:
            # positive_class_probability returns P(legitimate)
            legit_probs   = positive_class_probability(model, X_test)
            phishing_probs = 1.0 - legit_probs
            probs = phishing_probs

        # Predict: phishing if P(phishing) >= 0.5, i.e. P(legit) < 0.5
        preds = (probs >= 0.5).astype(int)  # 1 = phishing prediction

        # y_test has 0=phishing, 1=legit.
        # We need preds in same space: 1 if phishing, 0 if legit
        # → flip so 1=phishing aligns with ROC convention
        y_test_phishing = 1 - y_test          # 1=phishing, 0=legit for ROC
        preds_phishing  = preds               # already 1 when phishing prob ≥ 0.5

        probs_dict[name] = probs
        preds_dict[name] = preds_phishing

        summary_rows.append({
            "Model":        name,
            "AUC Score":    roc_auc_score(y_test_phishing, probs),
            "Accuracy (%)": accuracy_score(y_test_phishing, preds_phishing) * 100,
            "Precision":    precision_score(y_test_phishing, preds_phishing),
            "Recall":       recall_score(y_test_phishing, preds_phishing),
            "F1-Score":     f1_score(y_test_phishing, preds_phishing),
        })

        print(f"\n{name} Classification Report:")
        print(classification_report(y_test_phishing, preds_phishing,
                                    target_names=["Legitimate", "Phishing"]))

        fig, ax = plt.subplots(figsize=(5, 4))
        ConfusionMatrixDisplay.from_predictions(
            y_test_phishing,
            preds_phishing,
            display_labels=["Legitimate", "Phishing"],
            cmap="Blues",
            normalize="true",
            ax=ax
        )
        ax.set_title(f"{name} Confusion Matrix")
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir,
                    f"{name.lower().replace(' ', '_')}_confusion_matrix.png"))
        plt.close()

    summary_df = pd.DataFrame(summary_rows)
    summary_df.to_csv(os.path.join(output_dir, "model_summary.csv"), index=False)

    print("\nFinal Model Performance Summary:")
    print(summary_df)

    # ROC comparison
    plt.figure(figsize=(8, 6))
    for name, probs in probs_dict.items():
        y_test_phishing = 1 - y_test
        fpr, tpr, _ = roc_curve(y_test_phishing, probs)
        roc_auc_val = auc(fpr, tpr)
        plt.plot(fpr, tpr, label=f"{name} (AUC = {roc_auc_val:.3f})")

    plt.plot([0, 1], [0, 1], "k--")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curve Comparison")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "roc_curve_comparison.png"))
    plt.close()

    # Model comparison bar chart
    if not summary_df.empty:
        x     = np.arange(len(summary_df["Model"]))
        width = 0.35

        fig, ax = plt.subplots(figsize=(8, 5))
        bars1 = ax.bar(x - width / 2, summary_df["AUC Score"] * 100, width,
                       label="AUC Score (%)")
        bars2 = ax.bar(x + width / 2, summary_df["Accuracy (%)"],   width,
                       label="Accuracy (%)")

        for bar in list(bars1) + list(bars2):
            height = bar.get_height()
            ax.annotate(
                f"{height:.2f}",
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center", va="bottom", fontsize=9
            )

        ax.set_xlabel("Model")
        ax.set_ylabel("Score (%)")
        ax.set_title("Model Comparison: AUC vs Accuracy")
        ax.set_xticks(x)
        ax.set_xticklabels(summary_df["Model"])
        ax.legend()
        ax.grid(axis="y", linestyle="--", alpha=0.7)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, "model_comparison_auc_accuracy.png"))
        plt.close()

    print(f"\nEvaluation reports saved inside: {output_dir}/")
    return summary_df


def print_url_report(url, phishing_prob, features_dict, show_features=False):
    legitimate_prob = 1 - phishing_prob
    label      = "Phishing" if phishing_prob >= 0.5 else "Legitimate"
    confidence = phishing_prob if label == "Phishing" else legitimate_prob

    risk = (
        "CRITICAL" if phishing_prob >= 0.8 else
        "HIGH"     if phishing_prob >= 0.6 else
        "MEDIUM"   if phishing_prob >= 0.4 else
        "LOW"
    )

    safe_count      = sum(1 for v in features_dict.values() if v ==  1)
    suspicious_count= sum(1 for v in features_dict.values() if v ==  0)
    dangerous_count = sum(1 for v in features_dict.values() if v == -1)

    print("\n" + "=" * 70)
    print(f"URL                    : {url}")
    print(f"Final Prediction       : {label}")
    print(f"Confidence             : {confidence * 100:.2f}%")
    print(f"Phishing Probability   : {phishing_prob * 100:.2f}%")
    print(f"Legitimate Probability : {legitimate_prob * 100:.2f}%")
    print(f"Risk Level             : {risk}")
    print(f"Safe: {safe_count} | Suspicious: {suspicious_count} | Dangerous: {dangerous_count}")

    if show_features:
        print("\nDetailed Feature Breakdown")
        for name, val in features_dict.items():
            status = "Safe" if val == 1 else ("Suspicious" if val == 0 else "Dangerous")
            print(f"{name:25} : {status}")


def get_single_phishing_probability(model, X_pca, model_name):
    """
    ANN: sigmoid output = P(legitimate) because labels were mapped to
         phishing=0, legit=1.  So P(phishing) = 1 - sigmoid_output.

    """
    if model_name == "ANN":
       
       
        legit_prob = float(model.predict(X_pca, verbose=0)[0][0])
        return 1.0 - legit_prob          # P(phishing)

    # sklearn models: classes_ = [0, 1] after remapping
    # Column 0 = P(class 0) = P(phishing)
    classes = list(model.classes_)
    phishing_index = classes.index(0)   # phishing class is 0
    return float(model.predict_proba(X_pca)[0][phishing_index])


def predict_url(url, model_name, scaler, pca, models, show_features=False):
    features_dict, feature_array = extract_all_features(url)

    X = np.array(feature_array).reshape(1, -1)
    if X.shape[1] != 30:
        raise ValueError(f"Expected 30 features, but got {X.shape[1]} features")

    X_scaled = scaler.transform(X)
    X_pca    = pca.transform(X_scaled)

    model        = models[model_name]
    phishing_prob = get_single_phishing_probability(model, X_pca, model_name)

    label           = "Phishing" if phishing_prob >= 0.5 else "Legitimate"
    legitimate_prob = 1 - phishing_prob
    confidence      = phishing_prob if label == "Phishing" else legitimate_prob

    print_url_report(url, phishing_prob, features_dict, show_features=show_features)

    return phishing_prob, legitimate_prob, confidence, label, features_dict


def batch_predict(urls, model_name, scaler, pca, models, max_workers=5):
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(predict_url, url, model_name, scaler, pca, models): url
            for url in urls
        }

        for future in as_completed(futures):
            url = futures[future]
            try:
                phishing_prob, legitimate_prob, confidence, label, feats = future.result()
                results.append({
                    "URL":                    url,
                    "Prediction":             label,
                    "Confidence":             f"{confidence * 100:.2f}%",
                    "Phishing Probability":   f"{phishing_prob * 100:.2f}%",
                    "Legitimate Probability": f"{legitimate_prob * 100:.2f}%"
                })
            except Exception as e:
                results.append({
                    "URL":        url,
                    "Prediction": "Error",
                    "Error":      str(e)
                })

    return pd.DataFrame(results)


def main():
    parser = argparse.ArgumentParser(description="PhishNet full pipeline")
    parser.add_argument("--data",        default="data/phishing.csv",
                        help="Path to phishing dataset CSV")
    parser.add_argument("--models-dir",  default="app/models",
                        help="Directory to save trained models")
    parser.add_argument("--reports-dir", default="reports",
                        help="Directory to save EDA/evaluation reports")
    parser.add_argument("--url",         default=None,
                        help="Optional URL to scan after training")
    parser.add_argument("--model",       default="Random Forest",
                        choices=["ANN", "Random Forest", "SVM"])
    args = parser.parse_args()

    os.makedirs(args.models_dir,  exist_ok=True)
    os.makedirs(args.reports_dir, exist_ok=True)

    df = pd.read_csv(args.data)

    run_eda(df, output_dir=args.reports_dir)

    feature_count = df.drop(["Index", "class"], axis=1, errors="ignore").shape[1]
    n_components  = min(16, feature_count)

    # prepare_data now remaps labels to {0, 1} before any model sees them
    X_pca, y, scaler, pca = prepare_data(
        df,
        pca_components=n_components,
        model_dir=args.models_dir
    )

    X_train, X_test, y_train, y_test = train_test_split(
        X_pca, y, test_size=0.2, random_state=42
    )

    ann_model = train_ann(X_train, y_train, model_dir=args.models_dir)
    rf_model  = train_random_forest(X_train, y_train, model_dir=args.models_dir)
    svm_model = train_svm(X_train, y_train, model_dir=args.models_dir)

    models = {
        "ANN":          ann_model,
        "Random Forest": rf_model,
        "SVM":           svm_model,
    }

    evaluate_models(models, X_test, y_test, output_dir=args.reports_dir)

    if args.url:
        if args.model == "ANN" and ann_model is None:
            raise RuntimeError("ANN selected, but TensorFlow/Keras is not available.")
        predict_url(args.url, args.model, scaler, pca, models, show_features=True)


if __name__ == "__main__":
    main()
