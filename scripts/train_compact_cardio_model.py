"""Train a compact cardiovascular runtime model suitable for deployment."""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


BASE_DIR = Path(__file__).resolve().parents[1]
DATASET_PATH = BASE_DIR / "health-models" / "data" / "cardio.csv"
MODEL_PATH = BASE_DIR / "health-models" / "models" / "cardio_model.pkl"
SCALER_PATH = BASE_DIR / "health-models" / "models" / "cardio_scaler.pkl"
METRICS_PATH = BASE_DIR / "health-models" / "reports" / "cardio_compact_model_metrics.json"
TARGET_COLUMN = "CARDIO_DISEASE"


def main():
    df = pd.read_csv(DATASET_PATH)
    X = df.drop(columns=[TARGET_COLUMN])
    y = df[TARGET_COLUMN]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    model = LogisticRegression(max_iter=2000)
    model.fit(X_train_scaled, y_train)

    y_pred = model.predict(X_test_scaled)
    y_prob = model.predict_proba(X_test_scaled)[:, 1]

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, MODEL_PATH, compress=3)
    joblib.dump(scaler, SCALER_PATH, compress=3)

    metrics = {
        "dataset": str(DATASET_PATH.relative_to(BASE_DIR)),
        "model_type": "LogisticRegression",
        "test_size": 0.2,
        "random_state": 42,
        "metrics": {
            "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
            "roc_auc": round(float(roc_auc_score(y_test, y_prob)), 4),
            "f1_score": round(float(f1_score(y_test, y_pred)), 4),
        },
        "artifacts": {
            "model_path": str(MODEL_PATH.relative_to(BASE_DIR)),
            "model_size_mb": round(MODEL_PATH.stat().st_size / 1024 / 1024, 4),
            "scaler_path": str(SCALER_PATH.relative_to(BASE_DIR)),
            "scaler_size_mb": round(SCALER_PATH.stat().st_size / 1024 / 1024, 4),
        },
        "feature_columns": list(X.columns),
    }

    METRICS_PATH.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
