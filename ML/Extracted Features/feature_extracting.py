import joblib
from sklearn.inspection import permutation_importance
import numpy as np

# Load your model
model = joblib.load(r'C:\Users\shrey\Downloads\SGP-II\ML\Clean Model Constituents\clean_Linux.joblib')

# Get model information
print(f"Model type: {type(model)}")
print(f"Expected features: {model.n_features_in_}")

# If it's an ensemble model, get more details
if hasattr(model, 'estimators_'):
    print(f"Number of estimators: {len(model.estimators_)}")

# Try to get feature names if available
if hasattr(model, 'feature_names_in_'):
    print("Feature names:", model.feature_names_in_)