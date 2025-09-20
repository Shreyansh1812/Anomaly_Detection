import os
import pandas as pd
from ML.modules.template_mining import LogTemplateMiner
from ML.modules.feature_extraction import template_count_features
from ML.modules.model_training import load_model, score_anomalies

def main():
    log_path = input("Enter the path to the log file to test: ").strip()
    linux_model_path = r"C:\Users\shrey\Downloads\SGP-II\ML\Clean Model Constituents\clean_Linux.joblib"
    try:
        with open(log_path, "r") as f:
            messages = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading log file: {e}")
        return
    miner = LogTemplateMiner()
    df_templates = miner.extract_templates(messages)
    df_templates['entity_id'] = df_templates.index
    tc = template_count_features(df_templates, template_col="template_id", entity_col="entity_id")
    test_feature_count = tc.shape[1]
    # Scan models
    # compatible_models = []
    # for fname in os.listdir(models_dir):
    #     if fname.endswith('.joblib'):
    #         model_path = os.path.join(models_dir, fname)
    #         try:
    #             model = load_model(model_path)
    #             n_features = getattr(model, 'n_features_in_', None)
    #             if n_features == test_feature_count:
    #                 compatible_models.append((fname, model))
    #         except Exception as e:
    #             print(f"Error loading model {fname}: {e}")
    # if not compatible_models:
    #     print(f"No compatible model found for {test_feature_count} features.")
    #     return
    # Directly load HDFS trained model
    try:
        model = load_model(linux_model_path)
        print(f"Using model: clean_Linux.joblib")
    except Exception as e:
        print(f"Error loading model clean_Linux.joblib: {e}")
        return
    # ...existing code...
    scores = score_anomalies(model, tc)
    print("Anomaly Scores:")
    print(scores)

if __name__ == "__main__":
    main()
