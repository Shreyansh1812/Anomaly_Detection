"""
Model training and scoring utilities for log anomaly detection.
- Isolation Forest
"""
import pandas as pd
from sklearn.ensemble import IsolationForest
from typing import Optional
import joblib

def train_isolation_forest(X: pd.DataFrame, contamination: float = 0.01, random_state: int = 42) -> IsolationForest:
    model = IsolationForest(contamination=0.2, random_state=42)
    model.fit(X)
    return model

def score_anomalies(model: IsolationForest, X: pd.DataFrame) -> pd.DataFrame:
    scores = model.decision_function(X)
    preds = model.predict(X)
    return pd.DataFrame({
        "anomaly_score": scores,
        "is_anomaly": preds == -1
    }, index=X.index)

def save_model(model: IsolationForest, path: str):
    joblib.dump(model, path)

def load_model(path: str) -> IsolationForest:
    return joblib.load(path)
