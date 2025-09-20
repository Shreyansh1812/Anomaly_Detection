import pandas as pd
from ML.modules.feature_extraction import template_count_features, tfidf_features, aggregate_features
from ML.modules.model_training import train_isolation_forest, score_anomalies

# Sample log data
df = pd.DataFrame({
    'entity_id': ['A', 'A', 'B', 'B'],
    'template_id': ['t1', 't2', 't1', 't3'],
    'message': ['error foo', 'warn bar', 'error foo', 'info baz'],
    'status': [200, 404, 200, 500],
    'bytes': [100, 200, 150, 300],
    'path': ['/a', '/b', '/a', '/c']
})

# Feature extraction
tc = template_count_features(df)
tfidf = tfidf_features(df)
agg = aggregate_features(df)

# Model training
model = train_isolation_forest(tc)
scores = score_anomalies(model, tc)
print(scores)