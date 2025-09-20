"""
Feature extraction utilities for log anomaly detection.
- Template counts
- TF-IDF
- Aggregates per entity/window
"""
import pandas as pd
from typing import List, Optional, Dict, Any
from sklearn.feature_extraction.text import TfidfVectorizer

def template_count_features(df: pd.DataFrame, template_col: str = "template_id", entity_col: str = "entity_id") -> pd.DataFrame:
    """Return template count vectors per entity."""
    counts = df.groupby([entity_col, template_col]).size().unstack(fill_value=0)
    return counts

def tfidf_features(df: pd.DataFrame, text_col: str = "message", entity_col: str = "entity_id") -> pd.DataFrame:
    """Return TF-IDF features per entity."""
    texts = df.groupby(entity_col)[text_col].apply(lambda x: " ".join(x.astype(str)))
    vectorizer = TfidfVectorizer(max_features=1000)
    tfidf = vectorizer.fit_transform(texts)
    return pd.DataFrame(tfidf.toarray(), index=texts.index, columns=vectorizer.get_feature_names_out())

def aggregate_features(df: pd.DataFrame, entity_col: str = "entity_id", time_col: Optional[str] = None) -> pd.DataFrame:
    """Return aggregate stats per entity (and time window if provided)."""
    group_cols = [entity_col] + ([time_col] if time_col else [])
    agg = df.groupby(group_cols).agg({
        "status": ["count", "nunique"],
        "bytes": ["sum", "mean", "std"],
        "path": "nunique"
    })
    agg.columns = ["_".join(col).strip() for col in agg.columns.values]
    return agg.reset_index()
