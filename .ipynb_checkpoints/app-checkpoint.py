from flask import Flask, request, jsonify
from flask_cors import CORS
import re, math, os
from urllib.parse import urlparse, parse_qs
import pandas as pd
import joblib

app = Flask(__name__)
CORS(app)

# Expect these files to be present in the same folder:
MODEL_FILE = os.environ.get("PHISH_MODEL", "url_phishshield.joblib")
FEATURE_NAMES_FILE = os.environ.get("PHISH_FEATURES", "feature_names.joblib")
LABEL_ENCODER_FILE = os.environ.get("PHISH_LABELS", "label_encoder.joblib")

# Load artifacts
model = joblib.load(MODEL_FILE)
feature_names = joblib.load(FEATURE_NAMES_FILE)
try:
    encoder = joblib.load(LABEL_ENCODER_FILE)
except Exception:
    encoder = None

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    counts = Counter(s)
    total = len(s)
    return -sum((c/total) * math.log2(c/total) for c in counts.values())

def extract_features(url: str) -> dict:
    try:
        parsed = urlparse(url)
    except Exception:
        parsed = urlparse("")

    host = parsed.hostname or ""
    netloc = parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""

    feats = {}
    # Core features seen in your notebook:
    feats["url_length"] = len(url)
    feats["num_dots"] = url.count(".")
    feats["num_hyphens"] = url.count("-")
    feats["num_digits"] = sum(ch.isdigit() for ch in url)
    feats["https"] = 1 if parsed.scheme == "https" else 0

    # Reasonable additions (safe defaults to 0 if not used by model):
    feats["domain_length"] = len(host)
    feats["has_subdomain"] = 1 if host.count(".") >= 2 else 0
    feats["tld_length"] = len(host.split(".")[-1]) if "." in host else 0
    feats["has_at_symbol"] = 1 if "@" in url else 0
    feats["has_port"] = 1 if (":" in netloc and not netloc.endswith(":")) else 0
    feats["num_query_params"] = len(parse_qs(query))
    # IP in hostname
    ip_re = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
    feats["has_ip"] = 1 if ip_re.match(host or "") else 0
    # Special characters
    specials = ["@", "?", "=", "&", "%", "$"]
    feats["special_char_count"] = sum(url.count(ch) for ch in specials)
    # Suspicious TLDs (from your notebook)
    suspicious_tlds = ["xyz","top","tk","ml","cf","gq"]
    feats["suspicious_tld"] = 1 if any((host.endswith("."+t) or host.endswith(t)) for t in suspicious_tlds) else 0
    # Path features
    feats["path_length"] = len(path)
    feats["path_depth"] = path.count("/") if path else 0
    feats["hyphen_in_domain"] = 1 if "-" in host else 0
    feats["userinfo_in_netloc"] = 1 if "@" in netloc else 0
    # Keywords
    suspicious_words = ["login","signin","verify","update","secure","account","bank","invoice","wallet"]
    feats["suspicious_word_count"] = sum(1 for w in suspicious_words if w in url.lower())
    # Shorteners
    shorteners = ["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","adf.ly","cutt.ly","shorturl.at"]
    feats["is_shortener"] = 1 if any(s in host for s in shorteners) else 0
    # Entropy
    feats["host_entropy"] = shannon_entropy(host)

    return feats

def to_dataframe(feat_dict: dict) -> pd.DataFrame:
    # Align to feature_names order (missing features default to 0)
    row = [feat_dict.get(name, 0) for name in feature_names]
    return pd.DataFrame([row], columns=feature_names)

def phishing_probability(df: pd.DataFrame) -> float:
    # We try to pick the phishing column from predict_proba
    proba = model.predict_proba(df)[0]
    # Determine which class index is "phishing"
    classes = None
    try:
        if encoder is not None:
            classes = list(encoder.classes_)
        else:
            classes = list(getattr(model, "classes_", []))
    except Exception:
        classes = list(getattr(model, "classes_", []))

    phish_idx = None
    if classes:
        lowered = [str(c).lower() for c in classes]
        for cand in ["phishing","malicious","phish","fraud","bad"]:
            if cand in lowered:
                phish_idx = lowered.index(cand)
                break
        if phish_idx is None:
            # If we can find 'legitimate', use the other column
            for cand in ["legitimate","benign","good","safe"]:
                if cand in lowered and len(classes) == 2:
                    phish_idx = 1 - lowered.index(cand)
                    break

    if phish_idx is None:
        # Fallback: assume binary and take the higher-risk index as 1
        phish_idx = 1 if len(proba) > 1 else 0

    return float(proba[phish_idx])

@app.get("/score")
def score():
    url = request.args.get("url", "").strip()
    if not url:
        return jsonify(error="Missing url parameter"), 400
    feats = extract_features(url)
    df = to_dataframe(feats)
    try:
        p = phishing_probability(df)
    except Exception as e:
        return jsonify(error=f"Model error: {e}"), 500

    pct = int(round(p * 100))
    color = "red" if pct >= 70 else ("orange" if pct >= 30 else "green")
    label = "phishing" if pct >= 50 else "legitimate"
    advice = (
        "High risk. Do not enter credentials or download anything."
        if pct >= 90 else
        "Risky. Proceed only if you fully trust the sender/site."
        if pct >= 70 else
        "Unclear. Double-check the URL, sender, and HTTPS certificate."
        if pct >= 50 else
        "Likely safe but be cautious with sensitive info."
        if pct >= 30 else
        "Looks safe. Stay alert for unusual requests."
    )

    return jsonify(
        url=url,
        predicted_label=label,
        phishing_score=pct,
        legitimate_score=max(0, 100 - pct),
        rating_color=color,
        advice=advice,
        features_used=feature_names
    )

@app.get("/classes")
def classes():
    try:
        if hasattr(model, "classes_"):
            classes = [str(c) for c in model.classes_]
        elif encoder is not None:
            classes = [str(c) for c in encoder.classes_]
        else:
            classes = []
    except Exception:
        classes = []
    return jsonify(classes=classes)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)
