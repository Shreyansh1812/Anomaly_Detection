import argparse
from pathlib import Path
import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import classification_report, confusion_matrix


def _load_artifacts(model_dir: Path):
    model_path = model_dir / "ctu_iforest_model.joblib"
    feat_path = model_dir / "ctu_featurizer.joblib"
    cols_path = model_dir / "ctu_feature_cols.txt"

    if not model_path.exists():
        raise FileNotFoundError(f"Model not found: {model_path}")
    if not feat_path.exists():
        raise FileNotFoundError(f"Featurizer not found: {feat_path}")
    if not cols_path.exists():
        raise FileNotFoundError(f"Feature columns list not found: {cols_path}")

    model = joblib.load(model_path)
    featurizer = joblib.load(feat_path)
    feature_cols = [ln.strip() for ln in cols_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    return model, featurizer, feature_cols


def coerce_numeric_df(d: pd.DataFrame) -> pd.DataFrame:
    """Shim to satisfy pickled FunctionTransformer references (defined in training scripts).
    Coerces columns to numeric, replaces inf with NaN, fills NaNs with 0.
    """
    d2 = d.apply(pd.to_numeric, errors="coerce")
    d2 = d2.replace([np.inf, -np.inf], np.nan)
    return d2.fillna(0)


def _labels_to_binary(labels: pd.Series) -> np.ndarray:
    # Map label -> 0 (normal) / 1 (anomaly)
    # Treat 'benign', 'normal', 'background' as normal; everything else anomaly
    s = labels.astype(str).str.lower().str.strip()
    normal = s.isin(["benign", "normal", "background"]) | s.str.contains(r"^benign$|^normal$|^background$", regex=True)
    y_true = (~normal).astype(int).to_numpy()
    return y_true


def evaluate(model_dir: str, test_data_path: str):
    """
    Loads a trained model and evaluates its performance on test data.
    """
    print("--- Starting Evaluation ---")

    # 1. Load the saved model, featurizer, and feature columns
    model_dir_path = Path(model_dir)
    model, featurizer, feature_cols = _load_artifacts(model_dir_path)
    print(f"Loaded model and featurizer from {model_dir}")

    # 2. Load the test data
    test_path = Path(test_data_path)
    if not test_path.exists():
        raise FileNotFoundError(f"Test data not found: {test_path}")
    df = pd.read_csv(test_path)
    print(f"Loaded test data from {test_data_path} (rows={len(df):,})")

    if "label" not in df.columns:
        raise ValueError("Test data must contain a 'label' column for ground truth.")

    # 3. Prepare the test data
    # Ensure the DataFrame has exactly the columns expected by the featurizer
    # Missing columns are created with NaN; extra columns are dropped
    X_df = df.reindex(columns=feature_cols)
    X_test = featurizer.transform(X_df)
    print("Transformed test data using the featurizer.")

    # 4. Make predictions (+1 inlier/normal, -1 outlier/anomaly)
    y_pred_iforest = model.predict(X_test)
    # Convert to 0/1 where 1 = anomaly, 0 = normal
    y_pred = (y_pred_iforest == -1).astype(int)
    print("Made predictions on the test set.")

    # 5. Convert labels for evaluation (1 = anomaly, 0 = normal)
    y_true = _labels_to_binary(df["label"])
    print("Formatted labels and predictions for evaluation.")

    # 6. Calculate and print metrics
    print("\n--- Evaluation Results ---")
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    print("Confusion Matrix (rows=true, cols=pred):")
    print(cm)
    print()
    print(classification_report(y_true, y_pred, target_names=["normal", "anomaly"], digits=4))
    print("--- Evaluation Complete ---")


if __name__ == '__main__':
    # Set up argparse to handle command-line arguments
    parser = argparse.ArgumentParser(description="Evaluate a trained Isolation Forest model.")
    parser.add_argument("--model-dir", required=True, help="Directory containing model, featurizer, and feature columns")
    parser.add_argument("--test-data", required=True, help="Path to test CSV containing features and a 'label' column")

    args = parser.parse_args()

    # Call the evaluation function
    evaluate(args.model_dir, args.test_data)
