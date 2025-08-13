import argparse
import os
from pathlib import Path
from typing import List, Tuple

import numpy as np
import pandas as pd
from joblib import dump
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler, FunctionTransformer


def load_unsw_training(base_dir: Path, use_official_split: bool = True) -> pd.DataFrame:
    """Load UNSW-NB15 training data.

    If use_official_split=True, load UNSW_NB15_training-set.csv.
    Otherwise, tries to concat UNSW-NB15_1..4.csv (if present).
    """
    if use_official_split:
        f = base_dir / "UNSW_NB15_training-set.csv"
        if not f.exists():
            raise FileNotFoundError(f"Training set not found: {f}")
        df = pd.read_csv(f)
        return df
    # Fallback to split files
    parts = [base_dir / f"UNSW-NB15_{i}.csv" for i in range(1, 5)]
    existing = [p for p in parts if p.exists()]
    if not existing:
        raise FileNotFoundError("No UNSW-NB15 split files found (UNSW-NB15_1..4.csv)")
    dfs = [pd.read_csv(p) for p in existing]
    return pd.concat(dfs, ignore_index=True)


def coerce_numeric_df(d: pd.DataFrame) -> pd.DataFrame:
    """Coerce all columns to numeric, replace inf, and fill NaNs with 0."""
    d2 = d.apply(pd.to_numeric, errors="coerce")
    d2 = d2.replace([np.inf, -np.inf], np.nan)
    return d2.fillna(0)


def _align_columns(dfs: List[pd.DataFrame]) -> List[pd.DataFrame]:
    """Align all DataFrames to a union set of columns (fill missing with NaN)."""
    all_cols: List[str] = []
    seen = set()
    for d in dfs:
        for c in d.columns:
            if c not in seen:
                seen.add(c)
                all_cols.append(c)
    return [d.reindex(columns=all_cols) for d in dfs]


def load_unsw_all_files(base_dir: Path) -> pd.DataFrame:
    """Load and merge all available UNSW files: training, testing, and 1..4 splits."""
    candidates: List[Path] = []
    for name in ["UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv"]:
        p = base_dir / name
        if p.exists():
            candidates.append(p)
    for i in range(1, 5):
        p = base_dir / f"UNSW-NB15_{i}.csv"
        if p.exists():
            candidates.append(p)
    if not candidates:
        raise FileNotFoundError("No UNSW files found to load in 'all' mode.")

    dfs = [pd.read_csv(p) for p in candidates]
    dfs = _align_columns(dfs)
    return pd.concat(dfs, ignore_index=True)


def build_tabular_pipeline(df: pd.DataFrame) -> Tuple[Pipeline, List[str]]:
    """Build a preprocessing + feature pipeline for tabular UNSW data.

    Drops target/id/attack columns from features. One-hot encodes categoricals,
    scales numeric features. Returns pipeline and list of feature column names.
    """
    # Columns to drop from features
    drop_cols = {"id", "label", "attack_cat"}
    feature_cols = [c for c in df.columns if c not in drop_cols]

    X = df[feature_cols]
    # Infer types
    cat_cols = [c for c in X.columns if X[c].dtype == object]
    num_cols = [c for c in X.columns if c not in cat_cols]

    # OneHotEncoder kwargs (compat across sklearn versions)
    try:
        ohe = OneHotEncoder(handle_unknown="ignore", sparse_output=True)
    except TypeError:
        ohe = OneHotEncoder(handle_unknown="ignore", sparse=True)

    pre = ColumnTransformer(
        transformers=[
            ("cat", ohe, cat_cols),
            ("num", Pipeline([("coerce", FunctionTransformer(coerce_numeric_df, validate=False)),
                               ("scale", StandardScaler(with_mean=False))]), num_cols),
        ],
        remainder="drop",
        sparse_threshold=1.0,
    )

    pipe = Pipeline([
        ("ct", pre),
    ])
    return pipe, feature_cols


def train_iforest_on_unsw(df: pd.DataFrame, contamination: float = 0.02) -> Tuple[IsolationForest, Pipeline, List[str]]:
    # Prefer training on normal traffic only if labels exist
    use_df = df
    if "label" in df.columns:
        normal = df[df["label"] == 0]
        if not normal.empty:
            use_df = normal

    pipe, feature_cols = build_tabular_pipeline(use_df)
    X = pipe.fit_transform(use_df[feature_cols])

    model = IsolationForest(
        n_estimators=300,
        max_samples="auto",
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X)
    return model, pipe, feature_cols


def main():
    parser = argparse.ArgumentParser(description="Train IsolationForest on UNSW-NB15 (Australian Dataset)")
    parser.add_argument("--base", required=False, default=str(Path.cwd() / "Training Dataset" / "Australian Dataset"),
                        help="Base folder containing UNSW files")
    parser.add_argument("--out", required=False, default=str(Path.cwd() / "models" / "UNSW"),
                        help="Output directory for model artifacts")
    parser.add_argument("--contamination", type=float, default=0.02, help="IForest contamination rate")
    parser.add_argument("--use-official-split", action="store_true", help="Use UNSW_NB15_training-set.csv only")
    parser.add_argument("--all-files", action="store_true", help="Load and train on all UNSW files present")
    args = parser.parse_args()

    base_dir = Path(args.base)
    if args.all_files:
        df = load_unsw_all_files(base_dir)
    else:
        df = load_unsw_training(base_dir, use_official_split=args.use_official_split)

    print(f"Loaded UNSW rows: {len(df):,}")
    if "label" in df.columns:
        print(df["label"].value_counts(dropna=False).rename("count").to_string())
        if "attack_cat" in df.columns:
            print("Top attack categories:\n", df["attack_cat"].value_counts().head(10).to_string())

    model, pipe, feature_cols = train_iforest_on_unsw(df, contamination=args.contamination)

    out_dir = Path(args.out)
    os.makedirs(out_dir, exist_ok=True)
    model_path = out_dir / "unsw_iforest_model.joblib"
    pipe_path = out_dir / "unsw_featurizer.joblib"
    cols_path = out_dir / "unsw_feature_cols.txt"
    dump(model, model_path)
    dump(pipe, pipe_path)
    cols_path.write_text("\n".join(feature_cols), encoding="utf-8")
    print(f"Saved model: {model_path}")
    print(f"Saved featurizer: {pipe_path}")
    print(f"Saved feature columns: {cols_path}")


if __name__ == "__main__":
    main()
