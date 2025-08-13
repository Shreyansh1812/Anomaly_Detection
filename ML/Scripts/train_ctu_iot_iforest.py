import argparse
import os
from pathlib import Path
from typing import List, Tuple, Optional

import numpy as np
import pandas as pd
from joblib import dump
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler, FunctionTransformer


def coerce_numeric_df(d: pd.DataFrame) -> pd.DataFrame:
    d2 = d.apply(pd.to_numeric, errors='coerce')
    d2 = d2.replace([np.inf, -np.inf], np.nan)
    return d2.fillna(0)


def _align_columns(dfs: List[pd.DataFrame]) -> List[pd.DataFrame]:
    all_cols: List[str] = []
    seen = set()
    for d in dfs:
        for c in d.columns:
            if c not in seen:
                seen.add(c)
                all_cols.append(c)
    return [d.reindex(columns=all_cols) for d in dfs]


def load_ctu(base_dir: Path) -> pd.DataFrame:
    csvs = list(base_dir.glob('*.csv'))
    if not csvs:
        raise FileNotFoundError('No CTU IoT Malware CSV files found')
    dfs = [pd.read_csv(p) for p in csvs]
    dfs = _align_columns(dfs)
    return pd.concat(dfs, ignore_index=True)


def _count_rows(path: Path) -> int:
    # Count lines quickly; subtract 1 for header
    with path.open('rb') as f:
        count = sum(1 for _ in f)
    return max(0, count - 1)


def load_ctu_fast_sample(base_dir: Path, sample_rows: int, random_state: int = 42, chunksize: int = 200_000) -> pd.DataFrame:
    """Stream-sample rows across all CSVs without loading everything into memory.

    - Computes per-file sample sizes proportional to file row counts.
    - Iterates each file in chunks and samples a fraction of each chunk.
    - Stops once the per-file quota is reached.
    """
    rng = np.random.RandomState(random_state)
    csvs = list(base_dir.glob('*.csv'))
    if not csvs:
        raise FileNotFoundError('No CTU IoT Malware CSV files found')

    # Row counts per file
    counts = [ _count_rows(p) for p in csvs ]
    total = sum(counts)
    if total == 0:
        raise ValueError('All CTU CSVs are empty')

    targets = [ int(round(sample_rows * (c / total))) for c in counts ]
    # Adjust rounding differences
    diff = sample_rows - sum(targets)
    i = 0
    while diff != 0 and targets:
        j = i % len(targets)
        if diff > 0:
            targets[j] += 1
            diff -= 1
        else:
            if targets[j] > 0:
                targets[j] -= 1
                diff += 1
        i += 1

    sampled_chunks: List[pd.DataFrame] = []
    for path, target, n_rows in zip(csvs, targets, counts):
        if target <= 0 or n_rows == 0:
            continue
        take_frac = min(1.0, target / n_rows)
        taken = 0
        for chunk in pd.read_csv(path, chunksize=chunksize):
            if taken >= target:
                break
            # rows to take from this chunk (approx proportional)
            remaining = target - taken
            n_take = min(remaining, int(np.ceil(len(chunk) * take_frac)))
            if n_take <= 0:
                continue
            # sample without replacement within chunk
            idx = rng.choice(len(chunk), size=n_take, replace=False)
            sampled = chunk.iloc[idx]
            sampled_chunks.append(sampled)
            taken += len(sampled)
        # If we under-shot due to small chunks, we can top-up by concatenating last chunk fully; skip for simplicity

    if not sampled_chunks:
        raise ValueError('Sampling produced no data; check inputs')
    df = pd.concat(sampled_chunks, ignore_index=True)
    return df


def build_tabular_pipeline(df: pd.DataFrame) -> Tuple[Pipeline, List[str]]:
    # Try to drop obvious non-features if present
    drop_cols = {'label'}
    feature_cols = [c for c in df.columns if c not in drop_cols]
    X = df[feature_cols]
    cat_cols = [c for c in X.columns if X[c].dtype == object]
    num_cols = [c for c in X.columns if c not in cat_cols]
    try:
        ohe = OneHotEncoder(handle_unknown='ignore', sparse_output=True)
    except TypeError:
        ohe = OneHotEncoder(handle_unknown='ignore', sparse=True)
    pre = ColumnTransformer(
        transformers=[
            ('cat', ohe, cat_cols),
            ('num', Pipeline([('coerce', FunctionTransformer(coerce_numeric_df, validate=False)),
                              ('scale', StandardScaler(with_mean=False))]), num_cols),
        ],
        remainder='drop',
        sparse_threshold=1.0,
    )
    pipe = Pipeline([('ct', pre)])
    return pipe, feature_cols


def _prefer_normal(df: pd.DataFrame) -> pd.DataFrame:
    if 'label' in df.columns:
        normal_mask = df['label'].astype(str).str.lower().isin(['normal','benign','background'])
        normal = df[normal_mask]
        if not normal.empty:
            return normal
    return df


def _maybe_sample(df: pd.DataFrame, sample_rows: Optional[int], random_state: int = 42) -> pd.DataFrame:
    if sample_rows is None or len(df) <= sample_rows:
        return df
    frac = sample_rows / float(len(df))
    return df.sample(n=sample_rows, random_state=random_state) if frac < 1.0 else df


def train_iforest(
    df: pd.DataFrame,
    contamination: float = 0.02,
    sample_rows: Optional[int] = None,
    n_estimators: int = 100,
    n_jobs: int = 1,
) -> Tuple[IsolationForest, Pipeline, List[str]]:
    use_df = _prefer_normal(df)
    use_df = _maybe_sample(use_df, sample_rows)
    pipe, feature_cols = build_tabular_pipeline(use_df)
    X = pipe.fit_transform(use_df[feature_cols])
    model = IsolationForest(
        n_estimators=n_estimators,
        max_samples='auto',
        contamination=contamination,
        random_state=42,
        n_jobs=n_jobs,
    )
    model.fit(X)
    return model, pipe, feature_cols


def main():
    ap = argparse.ArgumentParser(description='Train IsolationForest on CTU IoT Malware dataset (all CSVs)')
    ap.add_argument('--base', default=str(Path.cwd() / 'Training Dataset' / 'Malware Detection'))
    ap.add_argument('--out', default=str(Path.cwd() / 'models' / 'CTU_IoT'))
    ap.add_argument('--contamination', type=float, default=0.02)
    ap.add_argument('--sample-rows', type=int, default=1500000, help='Subsample rows to avoid OOM (None to disable)')
    ap.add_argument('--n-estimators', type=int, default=100, help='Number of trees (lower reduces memory)')
    ap.add_argument('--n-jobs', type=int, default=1, help='Parallel jobs (1 reduces memory spikes)')
    ap.add_argument('--fast-sample', action='store_true', help='Stream-sample from CSVs instead of sampling after full load')
    args = ap.parse_args()

    base = Path(args.base)
    if args.fast_sample and args.sample_rows and args.sample_rows > 0:
        df = load_ctu_fast_sample(base, sample_rows=args.sample_rows)
        print(f'Loaded CTU IoT rows (fast-sampled): {len(df):,}')
    else:
        df = load_ctu(base)
        print(f'Loaded CTU IoT rows: {len(df):,}')
    if 'label' in df.columns:
        print('Label distribution (top 10):')
        print(df['label'].value_counts(dropna=False).head(10).to_string())

    model, pipe, feature_cols = train_iforest(
        df,
        contamination=args.contamination,
        sample_rows=args.sample_rows if args.sample_rows > 0 else None,
        n_estimators=args.n_estimators,
        n_jobs=args.n_jobs,
    )

    out_dir = Path(args.out)
    os.makedirs(out_dir, exist_ok=True)
    dump(model, out_dir / 'ctu_iforest_model.joblib')
    dump(pipe, out_dir / 'ctu_featurizer.joblib')
    (out_dir / 'ctu_feature_cols.txt').write_text('\n'.join(feature_cols), encoding='utf-8')
    print(f'Saved model: {out_dir / "ctu_iforest_model.joblib"}')
    print(f'Saved featurizer: {out_dir / "ctu_featurizer.joblib"}')
    print(f'Saved feature columns: {out_dir / "ctu_feature_cols.txt"}')


if __name__ == '__main__':
    main()
