import json
import re
from collections import Counter
from functools import lru_cache

import numpy as np
from django.conf import settings
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

MODEL_VERSION = "hybrid-sklearn-shap-v1"

CATEGORY_TEMPLATES = {
    "SUSPICIOUS_LOGIN": [
        "failed password for invalid user from 203.0.113.10 repeated brute force login attempts",
        "multiple failed authentication attempts against admin account from unusual location",
        "impossible travel login detected for user after successful password authentication",
        "password spraying attempt against several accounts with invalid credentials",
        "ssh authentication failure burst from external address against bastion host",
        "login replay anomaly and credential stuffing pattern observed onvpn gateway",
        "brute force login attempts using common passwords against web application",
        "successful login after repeated failures with mismatched user agent",
    ],
    "MALWARE": [
        "antivirus detected trojan executable and quarantined malicious binary",
        "malware beacon detected from endpoint to known command and control domain",
        "ransomware note file created and suspicious encryption behavior observed",
        "edr flagged malicious powershell script downloading payload from external host",
        "trojan dropper detected in email attachment with embedded macro",
        "endpoint scanner found worm-like propagation and infected shared drive files",
        "malicious hash matched on endpoint process with persistence registry key",
        "spyware signature detected in downloaded executable and network beacon",
    ],
    "NETWORK_INTRUSION": [
        "port scan detected from external address against multiple internal hosts",
        "network intrusion detection signature matched sql injection payload",
        "unexpected outbound connection to unusual port and suspicious ip address",
        "nids alert for command injection attempt against public web server",
        "lateral movement scan using smb ports across internal subnet",
        "dns tunneling pattern detected with long encoded query names",
        "firewall alert for syn flood and denial of service traffic burst",
        "unauthorized vpn connection attempt from unexpected country",
    ],
    "PHISHING": [
        "user reported phishing email with credential harvesting login page",
        "malicious email contains link to lookalike domain requesting password",
        "phishing campaign detected with invoice attachment and suspicious sender",
        "safe email gateway quarantined message with credential theft keywords",
        "spear phishing message targeting finance team with fake payment portal",
        "email security alert for_reply-to mismatch and malicious url shortener",
        "user clicked suspicious link and submitted credentials to cloned login page",
        "business email compromise attempt requesting urgent wire transfer",
    ],
    "PRIVILEGE_ESCALATION": [
        "privilege escalation attempt using sudo command from unprivileged account",
        "domain admin group membership added without approved change ticket",
        "role binding created granting cluster admin to unexpected service account",
        "kerberos ticket anomaly with privileged account and unusual workstation",
        "service account added to administrators group by unexpected identity",
        "privilege escalation exploit detected with suspicious process lineage",
        "iam policy changed to allow wildcard actions on production account",
        "local administrator password reset and privileged session opened",
    ],
    "OTHER": [
        "generic policy violation detected by correlation rule",
        "asset inventory drift observed for managed endpoint",
        "configuration baseline deviation reported by compliance scanner",
        "unknown event received from security sensor with limited detail",
        "scheduled maintenance event recorded by monitoring agent",
        "backup failure notification from infrastructure monitoring",
        "certificate expiration warning for internal service",
        "application error rate increase reported by telemetry rule",
    ],
}

CATEGORY_RULES = {
    "SUSPICIOUS_LOGIN": [
        (r"failed password|authentication failure|login failure", 3),
        (r"brute.?force|password spray|credential stuff", 3),
        (r"impossible travel|unusual location|invalid user", 2),
    ],
    "MALWARE": [
        (r"malware|trojan|ransomware|worm|spyware", 4),
        (r"malicious (?:file|binary|hash|script|payload)", 3),
        (r"command and control|beacon|quarantine", 2),
    ],
    "NETWORK_INTRUSION": [
        (r"port scan|syn flood|network intrusion|nids", 4),
        (r"sql injection|command injection|dns tunnel", 3),
        (r"lateral movement|unauthorized connection|outbound connection", 2),
    ],
    "PHISHING": [
        (r"phish|credential harvest|credential theft", 4),
        (r"lookalike domain|fake payment|wire transfer", 3),
        (r"malicious email|malicious url|attachment", 2),
    ],
    "PRIVILEGE_ESCALATION": [
        (r"privilege escalation|sudo|exploit", 4),
        (r"domain admin|cluster admin|administrators group", 3),
        (r"policy changed|wildcard actions|privileged session", 2),
    ],
    "OTHER": [(r"policy violation|baseline deviation|inventory drift", 2)],
}

SEVERITY_SCORE = {"LOW": 10, "MEDIUM": 25, "HIGH": 40, "CRITICAL": 55}
CATEGORY_SCORE = {
    "SUSPICIOUS_LOGIN": 12,
    "MALWARE": 20,
    "NETWORK_INTRUSION": 18,
    "PHISHING": 14,
    "PRIVILEGE_ESCALATION": 22,
    "OTHER": 4,
}
NUMERIC_FEATURE_NAMES = [
    "text_length",
    "digit_ratio",
    "severity_level",
    "failed_terms",
    "malware_terms",
    "network_terms",
    "phishing_terms",
    "privilege_terms",
    "indicator_terms",
]


def build_alert_text(alert):
    normalized = alert.normalized or {}
    parts = [
        alert.title,
        alert.description,
        normalized.get("alert_type", ""),
        normalized.get("user_identity", ""),
        normalized.get("source_ip", ""),
        normalized.get("destination_ip", ""),
        json.dumps(alert.raw_payload or {}, sort_keys=True),
    ]
    return " ".join(str(part) for part in parts if part)[:12000]


def _training_examples():
    texts = []
    labels = []
    for category, examples in CATEGORY_TEMPLATES.items():
        for text in examples:
            texts.append(text)
            labels.append(category)
            texts.append(f"{text} severity high observed by security sensor")
            labels.append(category)
    return texts, labels


def _numeric_features(text, severity):
    lower = text.lower()
    length = len(lower)
    digits = sum(char.isdigit() for char in lower)
    return np.array(
        [
            min(length / 100.0, 20.0),
            digits / max(length, 1),
            {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(severity, 1),
            lower.count("failed") + lower.count("brute"),
            lower.count("malware") + lower.count("trojan") + lower.count("ransomware"),
            lower.count("scan") + lower.count("injection") + lower.count("tunnel"),
            lower.count("phish") + lower.count("email") + lower.count("credential"),
            lower.count("admin") + lower.count("privilege") + lower.count("policy"),
            lower.count(".") + lower.count("http") + len(re.findall(r"\b[0-9a-f]{32,64}\b", lower)),
        ],
        dtype=float,
    )


@lru_cache(maxsize=1)
def get_models():
    texts, labels = _training_examples()
    text_model = Pipeline(
        [
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
            (
                "lr",
                LogisticRegression(max_iter=2000, random_state=42, class_weight="balanced"),
            ),
        ]
    )
    text_model.fit(texts, labels)
    numeric_matrix = np.vstack([_numeric_features(text, "MEDIUM") for text in texts])
    numeric_model = Pipeline(
        [
            ("scaler", StandardScaler()),
            ("lr", LogisticRegression(max_iter=2000, random_state=42, class_weight="balanced")),
        ]
    )
    numeric_model.fit(numeric_matrix, labels)
    return text_model, numeric_model, numeric_matrix


def model_info():
    texts, labels = _training_examples()
    text_model, _, _ = get_models()
    category_counts = Counter(labels)
    return {
        "model_version": MODEL_VERSION,
        "approach": "hybrid rules + TF-IDF logistic regression + numeric features",
        "categories": [
            {"label": label, "training_examples": count}
            for label, count in sorted(category_counts.items())
        ],
        "training_examples": len(texts),
        "vocabulary_size": len(text_model.named_steps["tfidf"].vocabulary_),
        "shap_enabled": settings.ENABLE_SHAP_EXPLAINER,
        "disclaimer": settings.AI_MODEL_DISCLAIMER,
    }


def _rule_scores(text):
    scored = []
    totals = {category: 0 for category in CATEGORY_RULES}
    lower = text.lower()
    for category, rules in CATEGORY_RULES.items():
        for pattern, weight in rules:
            if re.search(pattern, lower):
                totals[category] += weight
                scored.append({"category": category, "pattern": pattern, "weight": weight})
    return totals, scored


def _top_terms(text_model, text):
    try:
        vector = text_model.named_steps["tfidf"].transform([text])
        names = text_model.named_steps["tfidf"].get_feature_names_out()
        scores = vector.toarray()[0]
        indices = np.argsort(scores)[-6:][::-1]
        return [
            {"term": names[index], "weight": round(float(scores[index]), 3)}
            for index in indices
            if scores[index] > 0
        ]
    except Exception:
        return []


def _shap_drivers(numeric_model, numeric_matrix, text, severity):
    if not settings.ENABLE_SHAP_EXPLAINER:
        return []
    try:
        import shap

        class LinearProxy:
            coef_ = numeric_model.named_steps["lr"].coef_[0]
            intercept_ = numeric_model.named_steps["lr"].intercept_[0]

        background = np.mean(numeric_matrix, axis=0, keepdims=True)
        values = np.array([_numeric_features(text, severity)])
        explainer = shap.LinearExplainer(LinearProxy(), background)
        shap_values = np.asarray(explainer.shap_values(values))
        if shap_values.ndim == 3:
            shap_values = shap_values[0]
        impacts = shap_values[0]
        ranked = sorted(
            range(len(NUMERIC_FEATURE_NAMES)),
            key=lambda index: abs(float(impacts[index])),
            reverse=True,
        )[:3]
        return [
            {
                "feature": NUMERIC_FEATURE_NAMES[index],
                "effect": round(float(impacts[index]), 3),
            }
            for index in ranked
            if abs(float(impacts[index])) > 0.0001
        ]
    except Exception:
        return []


def classify_text(text, severity):
    text_model, numeric_model, numeric_matrix = get_models()
    rule_totals, matched_rules = _rule_scores(text)
    probabilities = text_model.predict_proba([text])[0]
    classes = list(text_model.classes_)
    best_index = int(np.argmax(probabilities))
    model_category = classes[best_index]
    model_confidence = float(probabilities[best_index])
    rule_category = max(rule_totals, key=rule_totals.get)
    rule_score = rule_totals[rule_category]
    rule_confidence = min(0.98, 0.52 + 0.07 * rule_score) if rule_score else 0.2

    if rule_score >= 4:
        category = rule_category
        confidence = max(rule_confidence, model_confidence)
        method = "HYBRID"
    elif model_confidence >= 0.45:
        category = model_category
        confidence = model_confidence
        method = "ML"
    else:
        category = rule_category if rule_score else model_category
        confidence = max(rule_confidence, model_confidence)
        method = "RULES" if rule_score else "ML"

    risk_score = min(
        100,
        SEVERITY_SCORE.get(severity, 25)
        + CATEGORY_SCORE.get(category, 4)
        + int(confidence * 20)
        + min(10, rule_score * 2),
    )
    return {
        "category": category,
        "risk_score": risk_score,
        "confidence": round(confidence, 3),
        "method": method,
        "model_version": MODEL_VERSION,
        "explanation": {
            "summary": (
                f"Category selected by {method.lower()} using matched rules and "
                "a deterministic text classifier."
            ),
            "matched_rules": matched_rules,
            "top_terms": _top_terms(text_model, text),
            "shap_drivers": _shap_drivers(numeric_model, numeric_matrix, text, severity),
        },
        "evidence": {
            "text_excerpt": text[:500],
            "severity": severity,
            "model_confidence": round(model_confidence, 3),
            "rule_score": rule_score,
            "rule_category": rule_category,
        },
    }


def classify_alert(alert):
    return classify_text(build_alert_text(alert), alert.severity)
