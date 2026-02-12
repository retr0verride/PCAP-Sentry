"""
Enhanced ML Training Module for PCAP Sentry

Uses all available data sources:
- Knowledge base (labeled safe/malware captures)
- Threat intelligence (online reputation data)
- Heuristic features
- Network behavior patterns
"""

import os
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

    def __init__(self, model_path: str = "pcap_sentry_model.pkl"):
        self.model_path = model_path
        self.vectorizer = None
        self.model = None

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

        # Train logistic regression model
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
        """Save trained model to disk"""
        if self.model is None or self.vectorizer is None:
            return False
        try:
            joblib.dump({
                "model": self.model,
                "vectorizer": self.vectorizer,
            }, self.model_path)
            print(f"[INFO] Model saved to {self.model_path}")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to save model: {e}")
            return False

    def load_model(self) -> bool:
        """Load trained model from disk"""
        if not os.path.exists(self.model_path):
            return False
        try:
            data = joblib.load(self.model_path)
            self.model = data.get("model")
            self.vectorizer = data.get("vectorizer")
            print(f"[INFO] Model loaded from {self.model_path}")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to load model: {e}")
            return False

    def predict(self, features: Dict) -> Tuple[Optional[str], Optional[float]]:
        """
        Make prediction on new features
        Returns: (label, malicious_probability)
        """
        if self.model is None or self.vectorizer is None:
            return None, None

        try:
            X = self.vectorizer.transform([vectorize_features(features)])
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
            "classes": list(self.model.classes_),
            "feature_count": len(self.vectorizer.get_feature_names_out()) if self.vectorizer else 0,
            "model_type": "logistic_regression",
            "backend": "cpu",
        }


def vectorize_features(features: Dict) -> Dict:
    """Convert feature dict to ML-ready format"""
    vector = {
        "packet_count": float(features.get("packet_count", 0)),
        "avg_size": float(features.get("avg_size", 0.0)),
        "dns_query_count": float(features.get("dns_query_count", 0)),
        "http_request_count": float(features.get("http_request_count", 0)),
        "unique_http_hosts": float(features.get("unique_http_hosts", 0)),
        # Threat intelligence features
        "flagged_ip_count": float(features.get("flagged_ip_count", 0)),
        "flagged_domain_count": float(features.get("flagged_domain_count", 0)),
        "avg_ip_risk_score": float(features.get("avg_ip_risk_score", 0.0)),
        "avg_domain_risk_score": float(features.get("avg_domain_risk_score", 0.0)),
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
