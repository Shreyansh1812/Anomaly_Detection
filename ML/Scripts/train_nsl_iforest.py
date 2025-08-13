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


NSL_COLUMNS = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent','hot',
    'num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root','num_file_creations',
    'num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count','srv_count',
    'serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
    'srv_diff_host_rate','dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate','label','difficulty'
]


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


def load_nsl(base_dir: Path, all_files: bool = False, use_20_percent: bool = False) -> pd.DataFrame:
    files: List[Path] = []
    if use_20_percent:
        files.append(base_dir / 'KDDTrain+_20Percent.txt')
        if all_files:
            files.append(base_dir / 'KDDTest-21.txt')
    else:
        files.append(base_dir / 'KDDTrain+.txt')
        if all_files:
            files.append(base_dir / 'KDDTest+.txt')
    candidates = [p for p in files if p.exists()]
    if not candidates:
        raise FileNotFoundError('No NSL-KDD files found. Expected KDDTrain+.txt (and optionally KDDTest+.txt).')
    dfs = [pd.read_csv(p, header=None, names=NSL_COLUMNS, sep=',') for p in candidates]
    dfs = _align_columns(dfs)
    return pd.concat(dfs, ignore_index=True)


def build_tabular_pipeline(df: pd.DataFrame) -> Tuple[Pipeline, List[str]]:
    drop_cols = {'difficulty', 'label'}
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


def train_iforest_on_nsl(df: pd.DataFrame, contamination: float = 0.02) -> Tuple[IsolationForest, Pipeline, List[str]]:
    use_df = df
    if 'label' in df.columns:
        normal_mask = df['label'].astype(str).str.lower().str.startswith('normal')
        normal = df[normal_mask]
        if not normal.empty:
            use_df = normal
    pipe, feature_cols = build_tabular_pipeline(use_df)
    X = pipe.fit_transform(use_df[feature_cols])
    model = IsolationForest(n_estimators=300, max_samples='auto', contamination=contamination, random_state=42, n_jobs=-1)
    model.fit(X)
    return model, pipe, feature_cols


def main():
    ap = argparse.ArgumentParser(description='Train IsolationForest on NSL-KDD dataset')
    ap.add_argument('--base', default=str(Path.cwd() / 'Training Dataset' / 'NSL-KDD'))
    ap.add_argument('--out', default=str(Path.cwd() / 'models' / 'NSL'))
    ap.add_argument('--contamination', type=float, default=0.02)
    ap.add_argument('--all-files', action='store_true', help='Include test split as well')
    ap.add_argument('--use-20-percent', action='store_true', help='Use KDDTrain+_20Percent instead of full train')
    args = ap.parse_args()

    base = Path(args.base)
    df = load_nsl(base, all_files=args.all_files, use_20_percent=args.use_20_percent)

    print(f'Loaded NSL-KDD rows: {len(df):,}')
    if 'label' in df.columns:
        print(df['label'].value_counts(dropna=False).head(10).to_string())

    model, pipe, feature_cols = train_iforest_on_nsl(df, contamination=args.contamination)

    out_dir = Path(args.out)
    os.makedirs(out_dir, exist_ok=True)
    dump(model, out_dir / 'nsl_iforest_model.joblib')
    dump(pipe, out_dir / 'nsl_featurizer.joblib')
    (out_dir / 'nsl_feature_cols.txt').write_text('\n'.join(feature_cols), encoding='utf-8')
    print(f'Saved model: {out_dir / "nsl_iforest_model.joblib"}')
    print(f'Saved featurizer: {out_dir / "nsl_featurizer.joblib"}')
    print(f'Saved feature columns: {out_dir / "nsl_feature_cols.txt"}')


if __name__ == '__main__':
    main()
