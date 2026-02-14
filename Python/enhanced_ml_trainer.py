"""
Enhanced ML Training Module for PCAP Sentry

Uses all available data sources:
- Knowledge base (labeled safe/malware captures)
- Threat intelligence (online reputation data)
- Heuristic features
- Network behavior patterns
"""

import os
import hashlib
import hmac
import json
from typing import Dict, List, Tuple, Optional

try:
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.linear_model import LogisticRegression
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class EnhancedMLTrainer:
    """Enhanced ML trainer using multiple data sources"""

    # Machine-specific HMAC key: a random 32-byte secret persisted in the
    # app data directory.  Falls back to a deterministic key derived from
    # COMPUTERNAME/USERNAME only when the data dir is unavailable.
    @staticmethod
    def _init_hmac_key() -> bytes:
        app_data = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA") or os.path.expanduser("~")
        key_dir = os.path.join(app_data, "PCAP_Sentry")
        os.makedirs(key_dir, exist_ok=True)
        key_path = os.path.join(key_dir, ".model_hmac_key")
        if os.path.isfile(key_path):
            try:
                with open(key_path, "rb") as f:
                    key = f.read()
                if len(key) == 32:
                    return key
            except OSError:
                pass
        key = os.urandom(32)
        try:
            with open(key_path, "wb") as f:
                f.write(key)
        except OSError:
            pass
        return key

    _HMAC_KEY = _init_hmac_key.__func__(None)  # call staticmethod at class creation

    def __init__(self, model_path: str = "pcap_sentry_model.pkl"):
        self.model_path = model_path
        self.vectorizer = None
        self.model = None
        self.backend = "cpu"

    def train_from_knowledge_base(self, kb: Dict) -> Tuple[Optional[Dict], Optional[str]]:
        """
        Train model from knowledge base with all available features
        """
        if not SKLEARN_AVAILABLE:
            return None, "scikit-learn not available"

        # Collect training data
        training_rows = []
        labels = []

        # Process safe samples
        for entry in kb.get("safe", []):
            features = entry.get("features", {})
            training_rows.append(vectorize_features(features))
            labels.append("safe")

        # Process malicious samples
        for entry in kb.get("malicious", []):
            features = entry.get("features", {})
            training_rows.append(vectorize_features(features))
            labels.append("malicious")

        if len(set(labels)) < 2 or len(labels) < 2:
            return None, f"Insufficient training data: {len(training_rows)} samples, {len(set(labels))} classes"

        print(f"[INFO] Training on {len(training_rows)} samples ({len(kb.get('safe', []))} safe, {len(kb.get('malicious', []))} malicious)")
        print(f"[INFO] Feature types in training data: {set().union(*[set(row.keys()) for row in training_rows])}")

        # Convert to feature vectors
        self.vectorizer = DictVectorizer(sparse=True)
        X = self.vectorizer.fit_transform(training_rows)

        # Train logistic regression model (CPU fallback)
        self.model = LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            random_state=42,
            solver="lbfgs",
        )

        try:
            self.model.fit(X, labels)
            print(f"[INFO] Model trained successfully with {X.shape[1]} features")

            # Get feature importance (coefficients)
            feature_names = self.vectorizer.get_feature_names_out()
            coefficients = self.model.coef_[0]

            # Sort by importance
            top_features = sorted(
                zip(feature_names, coefficients),
                key=lambda x: abs(x[1]),
                reverse=True
            )

            print("[INFO] Top 10 most important features:")
            for feature, coeff in top_features[:10]:
                print(f"  - {feature}: {coeff:.4f}")

            self.backend = "cpu"
            return {
                "backend": "cpu",
                "model": self.model,
                "vectorizer": self.vectorizer,
                "feature_count": X.shape[1],
                "training_samples": len(training_rows),
                "training_labels": len(set(labels)),
            }, None

        except Exception as e:
            return None, f"Training failed: {str(e)}"

    def save_model(self) -> bool:
        """Save trained model to disk with HMAC integrity signature."""
        if self.model is None or self.vectorizer is None:
            return False
        try:
            joblib.dump({
                "model": self.model,
                "vectorizer": self.vectorizer,
            }, self.model_path)
            # Write HMAC signature alongside the model file
            self._write_hmac(self.model_path)
            print(f"[INFO] Model saved to {self.model_path}")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to save model: {e}")
            return False

    def load_model(self) -> bool:
        """Load trained model from disk with HMAC integrity verification."""
        if not os.path.exists(self.model_path):
            return False
        try:
            # Verify HMAC signature before loading (pickle is dangerous with untrusted data)
            if not self._verify_hmac(self.model_path):
                print("[SECURITY] Model file HMAC verification failed — refusing to load.")
                return False

            data = joblib.load(self.model_path)
            if not isinstance(data, dict):
                print("[SECURITY] Model file has unexpected format — refusing to load.")
                return False

            model = data.get("model")
            vectorizer = data.get("vectorizer")

            # Type-check deserialized objects before trusting them
            if not (hasattr(model, "predict") and hasattr(model, "predict_proba")):
                print("[SECURITY] Deserialized model has unexpected type — refusing to load.")
                return False
            if not (hasattr(vectorizer, "transform") and hasattr(vectorizer, "get_feature_names_out")):
                print("[SECURITY] Deserialized vectorizer has unexpected type — refusing to load.")
                return False

            self.model = model
            self.vectorizer = vectorizer
            self.backend = "cpu"

            print(f"[INFO] Model loaded from {self.model_path} (HMAC verified)")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to load model: {e}")
            return False

    def _hmac_path(self, model_path: str) -> str:
        """Return the path to the HMAC file for a given model file."""
        return model_path + ".hmac"

    def _write_hmac(self, model_path: str) -> None:
        """Compute and write an HMAC-SHA256 signature of the model file."""
        h = hmac.new(self._HMAC_KEY, digestmod=hashlib.sha256)
        with open(model_path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        with open(self._hmac_path(model_path), "w", encoding="utf-8") as f:
            f.write(h.hexdigest())

    def _verify_hmac(self, model_path: str) -> bool:
        """Verify the HMAC-SHA256 signature of the model file."""
        hmac_file = self._hmac_path(model_path)
        if not os.path.exists(hmac_file):
            print("[SECURITY] No HMAC file found for model — refusing to load. Please retrain.")
            return False
        try:
            with open(hmac_file, "r", encoding="utf-8") as f:
                expected = f.read().strip().lower()
            h = hmac.new(self._HMAC_KEY, digestmod=hashlib.sha256)
            with open(model_path, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
            return hmac.compare_digest(h.hexdigest().lower(), expected)
        except Exception:
            return False

    def predict(self, features: Dict) -> Tuple[Optional[str], Optional[float]]:
        """
        Make prediction on new features
        Returns: (label, malicious_probability)
        """
        if self.model is None or self.vectorizer is None:
            return None, None

        try:
            row = vectorize_features(features)
            X = self.vectorizer.transform([row])
            prediction = self.model.predict(X)[0]
            probability = None

            if hasattr(self.model, "predict_proba"):
                probas = self.model.predict_proba(X)[0]
                if "malicious" in list(self.model.classes_):
                    mal_idx = list(self.model.classes_).index("malicious")
                    probability = float(probas[mal_idx])

            return prediction, probability
        except Exception as e:
            print(f"[ERROR] Prediction failed: {e}")
            return None, None

    def get_model_info(self) -> Dict:
        """Get information about the trained model"""
        if self.model is None:
            return {"status": "not_trained"}

        return {
            "status": "trained",
            "classes": ["safe", "malicious"],
            "feature_count": len(self.vectorizer.get_feature_names_out()) if self.vectorizer else 0,
            "model_type": "logistic_regression",
            "backend": self.backend,
        }


def vectorize_features(features: Dict) -> Dict:
    """Convert feature dict to ML-ready format"""
    pkt_count = float(features.get("packet_count", 0))
    vector = {
        "packet_count": pkt_count,
        "avg_size": float(features.get("avg_size", 0.0)),
        "median_size": float(features.get("median_size", 0.0)),
        "dns_query_count": float(features.get("dns_query_count", 0)),
        "http_request_count": float(features.get("http_request_count", 0)),
        "unique_http_hosts": float(features.get("unique_http_hosts", 0)),
        "tls_packet_count": float(features.get("tls_packet_count", 0)),
        "unique_tls_sni": float(features.get("unique_tls_sni", 0)),
        "unique_src": float(features.get("unique_src", 0)),
        "unique_dst": float(features.get("unique_dst", 0)),
        "malware_port_hits": float(features.get("malware_port_hits", 0)),
        # Threat intelligence features
        "flagged_ip_count": float(features.get("flagged_ip_count", 0)),
        "flagged_domain_count": float(features.get("flagged_domain_count", 0)),
        "avg_ip_risk_score": float(features.get("avg_ip_risk_score", 0.0)),
        "avg_domain_risk_score": float(features.get("avg_domain_risk_score", 0.0)),
        # Derived ratios
        "dns_per_packet_ratio": float(features.get("dns_query_count", 0)) / max(pkt_count, 1.0),
    }

    # Protocol ratios
    proto_ratio = features.get("proto_ratio", {})
    for proto, ratio in proto_ratio.items():
        vector[f"proto_{proto}"] = float(ratio)

    # Top ports as binary features
    top_ports = features.get("top_ports", [])
    for port in top_ports:
        vector[f"port_{int(port)}"] = 1.0

    return vector


if __name__ == "__main__":
    # Test the enhanced trainer
    print("Enhanced ML Training Module")
    print("=" * 50)

    trainer = EnhancedMLTrainer()
    info = trainer.get_model_info()
    print(f"Model status: {info}")

    # Example: Train on sample data
    sample_kb = {
        "safe": [
            {
                "features": {
                    "packet_count": 1000,
                    "avg_size": 64.0,
                    "dns_query_count": 5,
                    "http_request_count": 10,
                    "unique_http_hosts": 2,
                    "flagged_ip_count": 0,
                    "flagged_domain_count": 0,
                    "avg_ip_risk_score": 0.0,
                    "avg_domain_risk_score": 0.0,
                    "proto_ratio": {"TCP": 0.6, "UDP": 0.4},
                    "top_ports": [80, 443],
                }
            }
        ],
        "malicious": [
            {
                "features": {
                    "packet_count": 5000,
                    "avg_size": 80.0,
                    "dns_query_count": 50,
                    "http_request_count": 100,
                    "unique_http_hosts": 20,
                    "flagged_ip_count": 3,
                    "flagged_domain_count": 2,
                    "avg_ip_risk_score": 65.0,
                    "avg_domain_risk_score": 72.0,
                    "proto_ratio": {"TCP": 0.7, "UDP": 0.3},
                    "top_ports": [8080, 4444, 9999],
                }
            }
        ],
    }

    if SKLEARN_AVAILABLE:
        model_bundle, error = trainer.train_from_knowledge_base(sample_kb)
        if model_bundle:
            print("\nTraining successful!")
            print(f"Model info: {trainer.get_model_info()}")
        else:
            print(f"Training failed: {error}")
    else:
        print("scikit-learn not available. Install with: pip install scikit-learn")
