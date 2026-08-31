"""
False Positive Reduction Module (Phase 4 Module 4.1).
Combines existing heuristic checks with ML-based classification (RandomForest),
signature-based heuristic overrides (FP_PATTERNS), and confidence score categorization.
"""

import csv
import logging
import os
import re
from typing import Dict, List, Optional, Tuple, Any

try:
    import joblib
    HAS_JOBLIB = True
except ImportError:
    HAS_JOBLIB = False

import numpy as np

logger = logging.getLogger(__name__)

# Heuristic Content-Types that do not render HTML scripts
NON_HTML_CONTENT_TYPES = [
    "application/json",
    "application/javascript",
    "application/pdf",
    "application/xml",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/svg+xml",
    "audio/",
    "video/",
    "application/octet-stream"
]

# Signature-based FP overrides
FP_PATTERNS = [
    {"response_code": 200, "content_length": 0},  # Empty responses
    {"response_code": 302, "location": "login"},  # Redirect loops
    {"tool": "gobuster", "status": "429"},        # Rate-limited
    {"response_code": 429}                        # Rate-limited generic
]


class FalsePositiveFilter:
    """Evaluates candidate findings using heuristic rules, signature patterns, and ML model predictions."""

    def __init__(self, model_path: str = "data/models/fp_model.joblib", scaler_path: str = "data/models/scaler.joblib"):
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.model = None
        self.scaler = None
        self._load_or_train_model()

    def _load_or_train_model(self):
        """Load trained ML model and scaler from disk or train an offline RandomForestClassifier."""
        if HAS_JOBLIB and os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            try:
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                logger.info("[FPFilter] Loaded trained ML model and scaler from disk.")
                return
            except Exception as e:
                logger.debug(f"[FPFilter] Loading joblib model failed: {e}")

        # Train fallback RandomForestClassifier if model file doesn't exist
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.preprocessing import StandardScaler

            training_file = "training_data.csv"
            if not os.path.exists(training_file) and os.path.exists(os.path.join("data", training_file)):
                training_file = os.path.join("data", training_file)
            X, y = [], []

            if os.path.exists(training_file):
                with open(training_file, "r", encoding="utf-8") as f:
                    reader = csv.reader(f)
                    next(reader, None)  # header
                    for row in reader:
                        if len(row) >= 8:
                            X.append([float(val) for val in row[:7]])
                            y.append(int(row[7]))

            if not X:
                # Default synthetic training dataset for offline validation
                X = [
                    [200, 1024, 45.2, 1, 2, 0, 0],
                    [404, 0, 12.1, 2, 3, 1, 0],
                    [200, 0, 15.0, 2, 1, 0, 0],
                    [302, 450, 110.5, 3, 2, 0, 1],
                    [500, 2048, 250.0, 4, 3, 1, 0],
                    [200, 512, 30.0, 1, 1, 0, 0],
                    [429, 120, 5.0, 2, 2, 1, 1]
                ]
                y = [1, 0, 0, 0, 1, 1, 0]

            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)

            clf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
            clf.fit(X_scaled, y)

            joblib.dump(clf, self.model_path)
            joblib.dump(scaler, self.scaler_path)
            self.model = clf
            self.scaler = scaler
            logger.info("[FPFilter] Offline RandomForest model trained and saved to disk.")
        except Exception as e:
            logger.warning(f"[FPFilter] ML model training fallback skipped: {e}")

    def extract_feature_vector(self, finding: Dict[str, Any], response_meta: Optional[Dict[str, Any]] = None) -> np.ndarray:
        """
        Extract numerical feature vector:
        [response_status_code, response_content_length, response_time_ms, tool_id, endpoint_depth, contains_error, waf_detected]
        """
        meta = response_meta or {}
        code = float(meta.get("status_code", finding.get("status_code", 200)))
        length = float(meta.get("content_length", finding.get("content_length", 0)))
        time_ms = float(meta.get("response_time_ms", finding.get("response_time_ms", 50.0)))

        tool_str = str(finding.get("tool") or finding.get("tool_name", "nmap")).lower()
        tool_map = {"nmap": 1, "gobuster": 2, "nuclei": 3, "sqlmap": 4, "nikto": 5}
        tool_id = float(tool_map.get(tool_str, 1))

        url = str(finding.get("url") or finding.get("location") or "")
        depth = float(url.count("/"))

        body = str(meta.get("response_body", finding.get("proof", ""))).lower()
        has_error = 1.0 if any(k in body for k in ["error", "exception", "warning"]) else 0.0
        waf = 1.0 if meta.get("waf_detected", finding.get("waf_detected", False)) else 0.0

        return np.array([[code, length, time_ms, tool_id, depth, has_error, waf]])

    def check_signature_fp(self, finding: Dict[str, Any], response_meta: Optional[Dict[str, Any]] = None) -> bool:
        """Check if finding matches hardcoded FP_PATTERNS signature overrides."""
        meta = response_meta or {}
        code = meta.get("status_code", finding.get("status_code"))
        length = meta.get("content_length", finding.get("content_length"))
        tool = str(finding.get("tool") or finding.get("tool_name", "")).lower()
        loc = str(finding.get("location") or finding.get("url") or "").lower()

        # Rule 1: Empty response with 200
        if code == 200 and length == 0:
            return True
        # Rule 2: Redirect loop to login
        if code == 302 and "login" in loc:
            return True
        # Rule 3: Rate limited
        if code == 429 or (tool == "gobuster" and str(code) == "429"):
            return True

        return False

    def predict_confidence_score(self, finding: Dict[str, Any], response_meta: Optional[Dict[str, Any]] = None) -> Tuple[float, str]:
        """
        Use model predict_proba() to get confidence_score (probability of class 1).
        Categories: HIGH (>0.85), MEDIUM (0.60-0.85), LOW (<0.60).
        """
        if self.check_signature_fp(finding, response_meta):
            return 0.05, "LOW"

        if self.model and self.scaler:
            try:
                vec = self.extract_feature_vector(finding, response_meta)
                vec_scaled = self.scaler.transform(vec)
                proba = float(self.model.predict_proba(vec_scaled)[0][1])
                proba = round(proba, 2)

                if proba > 0.85:
                    cat = "HIGH"
                elif proba >= 0.60:
                    cat = "MEDIUM"
                else:
                    cat = "LOW"
                return proba, cat
            except Exception as e:
                logger.debug(f"[FPFilter] ML predict proba error: {e}")

        # Fallback heuristic confidence scoring
        base = float(finding.get("confidence_score", 0.75))
        cat = "HIGH" if base > 0.85 else ("MEDIUM" if base >= 0.60 else "LOW")
        return base, cat

    def check_status_code(self, finding: Dict[str, Any]) -> Tuple[bool, str]:
        vuln_type = str(finding.get("type") or finding.get("vuln_type") or "").lower()
        title = str(finding.get("title") or "").lower()
        proof = str(finding.get("proof") or "").lower()
        if ("reflection" in vuln_type or "xss" in vuln_type or "unencoded" in title):
            status_match = re.search(r"status\s*(\d{3})", proof)
            if status_match and int(status_match.group(1)) >= 400:
                return False, f"Reflection finding rejected due to non-2xx status code: {status_match.group(1)}"
        return True, "Status code valid"

    def check_baseline_differential(self, finding: Dict[str, Any], baseline_body: str = "") -> Tuple[bool, str]:
        vuln_type = str(finding.get("type") or finding.get("vuln_type") or "").lower()
        if ("sql" in vuln_type or "verbose_error" in vuln_type):
            matched_error = finding.get("matched_error") or ""
            if matched_error and baseline_body and matched_error.lower() in baseline_body.lower():
                return False, f"Database error '{matched_error}' was already present in baseline response"
        return True, "Baseline differential valid"

    def check_tracer_reflection(self, finding: Dict[str, Any], response_body: str = "") -> Tuple[bool, str]:
        vuln_type = str(finding.get("type") or finding.get("vuln_type") or "").lower()
        tracer_used = finding.get("tracer_used")
        if ("reflection" in vuln_type or "xss" in vuln_type) and tracer_used:
            if response_body and tracer_used not in response_body:
                return False, f"Tracer string '{tracer_used}' was not found in response body"
        return True, "Tracer reflection valid"

    def check_content_type(self, finding: Dict[str, Any], content_type: str = "") -> Tuple[bool, str]:
        vuln_type = str(finding.get("type") or finding.get("vuln_type") or "").lower()
        ct_clean = (content_type or finding.get("content_type") or "").lower().strip()
        if ("reflection" in vuln_type or "xss" in vuln_type) and ct_clean:
            for non_html in NON_HTML_CONTENT_TYPES:
                if non_html in ct_clean:
                    return False, f"Reflection finding rejected for non-HTML Content-Type: '{ct_clean}'"
        return True, "Content-Type valid"

    def should_report_finding(self, finding: Dict[str, Any], response_meta: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """Run heuristic rules, signature patterns, and ML model predictions."""
        response_meta = response_meta or {}

        if self.check_signature_fp(finding, response_meta):
            return False, "Finding rejected by signature-based FP pattern override"

        valid, reason = self.check_status_code(finding)
        if not valid:
            return False, reason

        valid, reason = self.check_baseline_differential(finding, response_meta.get("baseline_body", ""))
        if not valid:
            return False, reason

        valid, reason = self.check_tracer_reflection(finding, response_meta.get("response_body", ""))
        if not valid:
            return False, reason

        valid, reason = self.check_content_type(finding, response_meta.get("content_type", ""))
        if not valid:
            return False, reason

        score, cat = self.predict_confidence_score(finding, response_meta)
        finding["confidence_score"] = score
        finding["confidence_category"] = cat

        if cat == "LOW":
            finding["manual_review_flag"] = True
            logger.info(f"[FPFilter] Finding '{finding.get('cve_id') or finding.get('title')}' assigned LOW confidence ({score}). Flagged for manual review.")

        return True, f"Finding passed FP checks with {cat} confidence ({score})"
